// MIT License
//
// Copyright (c) 2020 Sebastian Werner
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//

package falco

import (
	"context"
	"fmt"
	"go.uber.org/atomic"
	"go.uber.org/ratelimit"
	"golang.org/x/time/rate"
	"sync"
	"time"
)

type AsyncInvocationPhase struct {
	ID  string
	ctx context.Context

	//submissions
	submitted map[string]Invocation
	completed map[string]Invocation
	Payloads  []Invocation

	//rate-limiting
	query ratelimit.Limiter
	spawn *rate.Limiter
	//sync
	wg     sync.WaitGroup
	lock   sync.Mutex
	cancel context.CancelFunc

	//internals
	submissions atomic.Int64
	//output
	monitor ProgressMonitor
}

func NewPhase(ctx context.Context, id string, tasks []Invocation,
	requestsPerSeconds int, monitor ProgressMonitor) *AsyncInvocationPhase {
	jobCtx, cancel := context.WithCancel(ctx)
	job := &AsyncInvocationPhase{
		ID:        id,
		ctx:       jobCtx,
		spawn:     rate.NewLimiter(rate.Every(time.Minute/time.Duration(requestsPerSeconds)), 10),
		query:     ratelimit.New(requestsPerSeconds),
		monitor:   monitor,
		Payloads:  tasks,
		submitted: make(map[string]Invocation),
		completed: make(map[string]Invocation),
		cancel:    cancel,
	}
	if job.monitor != nil {
		job.monitor.Setup()
	}

	return job
}

func (j *AsyncInvocationPhase) Name() string {
	return j.ID
}

func (j *AsyncInvocationPhase) Done(payloadID string) {

	if j.submissions.Load() > 0 {
		j.wg.Done()
	}

	if j.monitor != nil {
		j.monitor.Advance(1)
	}

	if payload, err := j.SubmittedPayloadFromId(payloadID); err == nil {
		if _, ok := j.completed[payloadID]; ok {
			//we have an already done job, we ignore it.
			fmt.Printf("recived a task that was already complet %s\n", payloadID)
		} else {
			j.lock.Lock()
			//we only want to collect the first occorance of a payload
			j.completed[payloadID] = payload
			j.lock.Unlock()
		}
	} else {
		fmt.Printf("completed a tasks we did  not submit jet %s\n", payloadID)
	}

	j.submissions.Sub(1)
}

func (j *AsyncInvocationPhase) Wait() {
	if j.monitor != nil {
		j.monitor.Render()
	}

	waitDelegate := make(chan struct{})
	go func() {
		defer close(waitDelegate)
		j.wg.Wait()
	}()
	select {
	case <-waitDelegate:
	case <-j.ctx.Done():
	}

	if j.monitor != nil {
		j.monitor.Finish()
	}

}

func (j *AsyncInvocationPhase) Log(text string) {
	if j.monitor != nil {
		j.monitor.Info(text)
	}
}

func (j *AsyncInvocationPhase) WithTimeout(timeout time.Duration) error {
	waitDelegate := make(chan struct{})

	go func() {
		defer close(waitDelegate)
		j.Wait()
	}()

	select {
	case <-j.ctx.Done():
		return nil
	case <-waitDelegate:
		return nil
	case <-time.After(timeout):
		if j.monitor != nil {
			j.monitor.Finish()
		}
		j.Finish()
		return fmt.Errorf("timed out after %+v", timeout)
	}
}

func (j *AsyncInvocationPhase) Canceled() <-chan struct{} {
	return j.ctx.Done()
}

//TakeQuery enabels rate limiting for api requests, e.g. for requesting the status of an invocation
func (j *AsyncInvocationPhase) TakeQuery() time.Time {
	return j.query.Take()
}

//TakeInvocation enables rate limiting for invocation requests
func (j *AsyncInvocationPhase) TakeInvocation() time.Time {
	_ = j.spawn.Wait(j.ctx)
	return time.Now()
}

func (j *AsyncInvocationPhase) Finish() {
	j.cancel()
}

func (j *AsyncInvocationPhase) AsParentContext() context.Context {
	return j.ctx
}

//SubmittedTask is called to indicate that a payload was send to an invocation
func (j *AsyncInvocationPhase) SubmittedTask(payload Invocation) {
	j.lock.Lock()
	defer j.lock.Unlock()

	if j.monitor != nil {
		j.monitor.Expand(1)
	}

	j.wg.Add(1)
	j.submissions.Add(1)
	if _, ok := j.submitted[payload.ID()]; ok {
		payload.MarkAsResubmitted()
	}
	j.submitted[payload.ID()] = payload
}

func (j *AsyncInvocationPhase) SubmittedPayloadFromId(payloadID string) (Invocation, error) {
	j.lock.Lock()
	defer j.lock.Unlock()
	if val, ok := j.submitted[payloadID]; ok {
		return val, nil
	} else {
		return nil, fmt.Errorf("not yet submitted or unknown")
	}
}

func (j *AsyncInvocationPhase) PrintStats() {
	totalTime := time.Duration(0)
	failed := 0
	min := time.Now()
	for _, t := range j.completed {
		if t.Error() == nil {
			if t.SubmittedAt().Before(min) {
				min = t.SubmittedAt()
			}
			totalTime += t.InvocationDuration()
		} else {
			failed++
		}
	}

	if len(j.completed) > 0 {
		duration := time.Now().Sub(min)
		mean := time.Duration(int64(totalTime) / int64(len(j.completed)))

		fmt.Printf("job done with a mean task execution time of %+v a total runtime of %+v and %d failed requests\n",
			mean, duration, failed)

	} else {
		fmt.Printf("job done with %d failed requests\n",
			failed)
	}
}
