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

type ProgressMonitor interface {
	Setup()
	Advance(int)
	Expand(int)
	Render()
	Finish()
	Info(string)
}

type Job struct {
	ctx context.Context

	Context Context
	//
	Deployment Deployment
	//tasks
	Submitted  map[string]InvocationPayload
	Tasks []InvocationPayload

	//rate-limiting
	query ratelimit.Limiter
	spawn *rate.Limiter
	//sync
	wg   sync.WaitGroup
	lock sync.Mutex
	cancel  context.CancelFunc

	//internals
	tasks       atomic.Int64
	_waitCancel chan interface{}
	//output
	monitor ProgressMonitor

}

func NewJob(ctx context.Context,  tasks []InvocationPayload,
	requestsPerSeconds int, monitor ProgressMonitor,) *Job {
	jobCtx,cancel := context.WithCancel(ctx)
	job := &Job{
		ctx:   jobCtx,
		spawn: rate.NewLimiter(rate.Every(time.Minute/time.Duration(requestsPerSeconds)), 10),
		query: ratelimit.New(requestsPerSeconds),
		monitor : monitor,
		Tasks: tasks,
		Submitted: make(map[string]InvocationPayload),
		_waitCancel: make(chan interface{}),
		cancel:cancel,
	}
	if job.monitor != nil{
		job.monitor.Setup()
	}

	return job
}

func (j *Job) Add(delta int) {
	j.lock.Lock()
	defer j.lock.Unlock()

	if j.monitor != nil{
		j.monitor.Expand(delta)
	}

	j.wg.Add(delta)
	j.tasks.Add(1)
}

func (j *Job) Done() {
	if j.tasks.Load() > 0 {
		j.wg.Done()
	}

	if j.monitor != nil{
		j.monitor.Advance(1)
	}

	j.tasks.Sub(1)
}

func (j *Job) Wait() {
	if j.monitor != nil{
		j.monitor.Render()
	}

	waitDelegate := make(chan struct{})
	go func(){
		defer close(waitDelegate)
		j.wg.Wait()
	}()
	select {
		case <-waitDelegate:
		case <-j._waitCancel:
	}

	if j.monitor != nil{
		j.Finish()
	}

}

func (j *Job) Info(text string) {
	if j.monitor != nil{
		j.Info(text)
	}
}

func (j *Job) WithTimeout(timeout time.Duration) error {
	waitDelegate := make(chan struct{})

	go func() {
		defer close(waitDelegate)
		j.Wait()
	}()

	select {
	case <-j._waitCancel:
		return nil
	case <-waitDelegate:
		return nil
	case <-time.After(timeout):
		j.monitor.Finish()
		return fmt.Errorf("timed out after %+v", timeout)
	}
}

func (j *Job) Canceled() <-chan struct{} {
	return j.ctx.Done()
}

func (j *Job) TakeQuery() time.Time {
	return j.query.Take()
}

func (j *Job) TakeSpawn() time.Time {
	_ = j.spawn.Wait(j.ctx)
	return time.Now()
}

func (j *Job) Finish() {
	close(j._waitCancel)
}

func (j *Job) AsParentContext() context.Context {
	return j.ctx
}

func (j *Job) Cancel(){
	j.cancel()
	j.Finish()
}