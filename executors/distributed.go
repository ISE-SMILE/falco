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

package executors

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/ISE-SMILE/falco"
	"os"
	"os/signal"
	"time"
)

type StragglerStrategy interface {
	SelectStranglers(job *falco.Job, p *DistributedExecutor) ([]falco.InvocationPayload, []falco.InvocationPayload, int)
}

type DEQueueMessage interface {
	//returns payloadID refernece for this message
	PayloadID() string
	//returns the status of a invocation
	Status() falco.InvocationStatus

	Telemetry() []byte
}

type DEQueue interface {
	//called before any execution strategy, can be used to setup connections, check configurations
	Setup(*falco.Context) error

	//enables the channel, after this call messages send from the runtime shuld be recived and processed
	Start(jobname string) error
	//cleans up connections and closes all conumers
	Close() error
	//this call is used to observe updates on the job, without any telemetry
	Observe() (<-chan DEQueueMessage, error)
	//this call is used to observe updates on a job including telemetry data
	ConsumeMetrics() (<-chan DEQueueMessage, error)
}

type DeadlineStragglerStrategy struct {
	DeadlineDuration time.Duration
	ReTryThreshold   int8
}

func (d DeadlineStragglerStrategy) SelectStranglers(job *falco.Job, p *DistributedExecutor) ([]falco.InvocationPayload, []falco.InvocationPayload, int) {
	stranglers := make([]falco.InvocationPayload, 0)
	failures := make([]falco.InvocationPayload, 0)
	completed := 0
	for _, payload := range job.Tasks {
		if !payload.IsCompleted() && payload.GetNumberOfSubmissions() > 0 {
			//we consider this payload as problematic..
			executionTime := time.Now().Sub(payload.SubmittedAt())
			if executionTime > d.DeadlineDuration {
				fmt.Printf("payload %s is %+v over deadline, running for %+v\n", payload.ID(), executionTime-d.DeadlineDuration, executionTime)
				if payload.GetNumberOfSubmissions() < d.ReTryThreshold {
					stranglers = append(stranglers, payload)
				} else {
					failures = append(failures, payload)
				}
			}
		} else if payload.IsCompleted() {
			completed++
		}
	}
	return stranglers, failures, completed
}

type MeanBackoffStragglerStrategy struct {
	//maximum number of re-submissions before a straggler is makred as a failed request
	ReTryThreshold int8
	//the percentage of total task needed to calculate the mean execution time used as a threashold
	MinimumSampleSize *float32
	//addtional time over the mean exection time that a task is still not marked as a straggler
	Graceperiod time.Duration
}

func (m MeanBackoffStragglerStrategy) SelectStranglers(job *falco.Job, p *DistributedExecutor) ([]falco.InvocationPayload, []falco.InvocationPayload, int) {
	stranglers := make([]falco.InvocationPayload, 0)
	failures := make([]falco.InvocationPayload, 0)
	completed := 0

	totalExecutionTime := time.Duration(0)
	inflight := make([]falco.InvocationPayload, 0)
	for _, t := range job.Tasks {
		if t.IsCompleted() {
			completed++
			totalExecutionTime += t.Latancy()
		} else if t.GetNumberOfSubmissions() > 0 {
			if t.GetNumberOfSubmissions() >= m.ReTryThreshold {
				failures = append(failures, t)
			} else {
				//task is inflight
				inflight = append(inflight, t)
			}
		}
	}
	if completed > 0 {
		compleationRatio := float32(completed) / float32(len(job.Tasks))

		if (m.MinimumSampleSize == nil) || (m.MinimumSampleSize != nil && compleationRatio >= *m.MinimumSampleSize) {
			meanExecutionLatency := int64(totalExecutionTime) / int64(completed)
			for _, t := range inflight {
				executionTime := time.Now().Sub(t.SubmittedAt())
				if int64(executionTime) > meanExecutionLatency*int64(t.GetNumberOfSubmissions())+int64(m.Graceperiod) {
					stranglers = append(stranglers, t)
				}
			}
			fmt.Printf("current mean exec time is %+v, %d Straglers detected\n", time.Duration(meanExecutionLatency), len(stranglers))
		}
	}

	return stranglers, failures, completed

}

type DistributedExecutor struct {
	Queue        DEQueue
	Timeout      time.Duration
	TestInterval time.Duration
	Strategy     StragglerStrategy
}

func (p *DistributedExecutor) Execute(job *falco.Job, submittable falco.Submittable, writer falco.ResultCollector) error {

	err := p.Queue.Start(job.Name())
	if err != nil {
		return err
	}

	defer p.Queue.Close()

	//register an interrupt handler so we don't loose data ;)
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)
	signalContext, cancelSignalContext := context.WithCancel(context.Background())
	defer cancelSignalContext()
	go func() {
		select {
		case sig := <-signalChan:
			fmt.Printf("Got %s signal. Aborting...\n", sig)
			if err != nil {
				fmt.Printf("failed to write %+v\n", err)
			}
			job.Cancel()
		case <-signalContext.Done():
			return
		}
	}()

	//collect start

	go func() {
		collectMetrics := writer != nil
		if collectMetrics {
			err = p.collectMetrics(job, writer)
		} else {
			err = p.collectStage(job, writer)
		}

		if err != nil {
			job.Cancel()
			fmt.Printf("failed to collect stage, cause: %+v", err)
		}
	}()

	//collect end
	go p.observeJobs(job, submittable, writer)
	//submitt all tasks
	submitJobAsync(submittable, job.Tasks, job, nil)

	//wait for all results or timeout
	if p.Timeout > 0 {
		if job.WithTimeout(p.Timeout) != nil {
			time.Sleep(250 * time.Millisecond)
			job.Cancel()
			//grace-period to finish up writes
			time.Sleep(250 * time.Millisecond)
			fmt.Println("invoke timed out ...")
		}
	} else {
		job.Wait()
	}

	job.PrintStats()

	return err
}

func (p *DistributedExecutor) collectMetrics(job *falco.Job, writer falco.ResultCollector) error {
	metrics, err := p.Queue.ConsumeMetrics()

	if err != nil {
		return err
	}
	start := time.Now()
	for {
		select {
		case m := <-metrics:
			var data falco.Measurement
			err = json.Unmarshal(m.Telemetry(), &data)

			if data != nil {
				//TODO:!
				//data.withDefaults()
				payloadID := m.PayloadID()
				job.Done(payloadID)
				if payload, err := job.PayloadFromId(payloadID); err == nil {
					if !payload.IsCompleted() {
						payload.Done()
						if data.IsFailure() {
							payload.SetError(fmt.Errorf("runtime rrror - %s", data["failure"]))
						}
						data["fRate"] = payload.GetNumberOfSubmissions()
					}
				}

				data.SetInvocationID(payloadID)
				data.SetRequestLatency(time.Now().Sub(start))
				writer.Add(data)
			}

		case <-job.Canceled():
			return nil
		}
	}

}

func (p *DistributedExecutor) collectStage(job *falco.Job, writer falco.ResultCollector) error {
	acks, err := p.Queue.Observe()

	if err != nil {
		return err
	}

	for i := 0; i < len(job.Tasks); i++ {
		select {
		case x := <-acks:
			if payload, err := job.PayloadFromId(x.PayloadID()); err == nil {
				payload.Done()
				if x.Status() != falco.Success {
					payload.SetError(fmt.Errorf("runtime error"))
				}
			}

			job.Done(x.PayloadID())
		case <-job.Canceled():
			fmt.Println("job got canceled")
		}
	}

	return nil
}

func (p *DistributedExecutor) observeJobs(job *falco.Job, cmd falco.Submittable, writer falco.ResultCollector) {
	for {
		select {
		case <-time.After(p.TestInterval):
			stranglers, failiures, compleated := p.selectStranglers(job)
			if compleated == len(job.Tasks) {
				//TODO we are done
				fmt.Printf("terminate - all parts done")
				job.Finish()
			}
			//if verbose {
			//	job.Info(fmt.Sprintf("checking for stranglers...%d found\n",len(stranglers)))
			//}
			if len(stranglers) > 0 {
				//no need to wait for resubmitted jobs...
				for i := 0; i < len(stranglers); i++ {
					job.Info(fmt.Sprintf("%s\n", stranglers[i].ID()))
					job.Done("")
				}
				submitJobAsync(cmd, stranglers, job, nil)
			}
			for _, payload := range failiures {
				if !payload.IsCompleted() {
					job.Done(payload.ID())
					payload.SetError(fmt.Errorf("task timeout after %d tries", payload.GetNumberOfSubmissions()))
					payload.Done()

					payload.WriteError(writer)

				}
			}

		case <-job.Canceled():
			return
		}
	}
}

func (p *DistributedExecutor) selectStranglers(job *falco.Job) ([]falco.InvocationPayload, []falco.InvocationPayload, int) {
	return p.Strategy.SelectStranglers(job, p)
}
