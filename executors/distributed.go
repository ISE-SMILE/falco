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
	"github.com/streadway/amqp"
	"os"
	"os/signal"
	"strings"
	"time"
)

type StragglerStrategy interface {
	selectStranglers(job *falco.Job, p DistributedExecutor) ([]falco.InvocationPayload,[]falco.InvocationPayload,int)
}

type DeadlineStragglerStrategy struct {
	DeadlineDuration time.Duration
	ReTryThreshold   int8
}

func (d DeadlineStragglerStrategy) selectStranglers(job *falco.Job, p DistributedExecutor) ([]falco.InvocationPayload, []falco.InvocationPayload, int) {
	stranglers := make([]falco.InvocationPayload, 0)
	failures := make([]falco.InvocationPayload, 0)
	completed := 0
	for _, payload := range job.Submitted {
		if !payload.IsCompleted() {
			//we consider this payload as problematic..
			if payload.SubmittedAt().Add(d.DeadlineDuration).After(time.Now()) {
				//TODO: make this tuneable?
				if payload.GetNumberOfSubmissions() < d.ReTryThreshold {
					stranglers = append(stranglers, payload)
				} else {
					failures = append(failures, payload)
				}
			}
		} else {
			completed++
		}
	}
	return stranglers, failures, completed
}

type DistributedExecutor struct {
	QueueConnection *amqp.Connection
	Timeout         time.Duration
	TestInterval    time.Duration
	Strategy        StragglerStrategy
}

func (p DistributedExecutor) Execute(job *falco.Job, submittable falco.Submittable, writer *falco.ResultCollector) error {


	for _, payload := range job.Tasks {
		job.Submitted[payload.ID()] = payload
	}

	defer p.QueueConnection.Close()
	ch, err := p.QueueConnection.Channel()

	if err != nil {
		return err
	}
	defer ch.Close()

	//create the rabbitmq queues
	control_plane, err := ch.QueueDeclare(job.Context.Name(), false, false, false, false, nil)
	if err != nil {
		return err
	}



	data_plane, err := ch.QueueDeclare(fmt.Sprintf("%s-metrics", job.Context.Name()), false, false, false,
		false, nil)
	if err != nil {
		return err
	}

	//remove content of privious runs?
	_, _ = ch.QueuePurge(control_plane.Name, true)
	_, _ = ch.QueuePurge(data_plane.Name, true)

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

	//submitt setup end

	//collect start

	go func() {
		collectMetrics := writer != nil
		if collectMetrics {
			err = p.collectMetrics(job, ch, writer)
		} else {
			err = p.collectStage(job, ch, writer)
		}

		if err != nil {
			job.Cancel()
			fmt.Printf("failed to collect stage, cause: %+v", err)
		}
	}()

	//collect end
	go p.observeJobs(job,submittable,writer)
	//submitt all tasks
	submitJobAsync(submittable, job.Tasks, job, nil)


	//wait for all results or timeout
	if p.Timeout > 0 {
		if job.WithTimeout(p.Timeout) != nil {
			job.Cancel()
			//grace-period to finish up writes
			time.Sleep(500 * time.Millisecond)
			fmt.Println("invoke timed out ...")
		}
	} else {
		job.Wait()
	}
	_, _ = ch.QueueDelete(job.Context.Name(), false, false, false)
	_, _ = ch.QueueDelete(fmt.Sprintf("%s-metrics", job.Context.Name()), false, false, false)
	return err
}

func (p DistributedExecutor) collectMetrics( job *falco.Job, ch *amqp.Channel,
	writer *falco.ResultCollector) error {
	metrics, err := ch.Consume(
		fmt.Sprintf("%s-metrics", job.Context.Name()), // queue
		"",                                            // consumer
		true,                                          // auto-ack
		false,                                         // exclusive
		false,                                         // no-local
		false,                                         // no-wait
		nil,                                           // args
	)

	if err != nil {
		return err
	}
	start := time.Now()
	for {
		select {
		case m := <-metrics:
			var data falco.Measurement
			err = json.Unmarshal(m.Body, &data)

			if data != nil {
				//TODO:!
				//data.withDefaults()
				job.Done()
				payloadID := data.InvocationID()
				if payload,ok := job.Submitted[payloadID]; ok {
					if !payload.IsCompleted() {
						payload.Done();
						if data.IsFailure() {
							payload.SetError(fmt.Errorf("runtime rrror - %s",data["failure"]))
						}
						data["fRate"] = payload.Submitted()
					}
				}

				data.SetInvocationID(payloadID)
				data.SetRequestLatency(time.Now().Sub(start))
				writer.Add(data)
			}


		case <-job.Canceled():
			fmt.Println("job got canceled")
			return nil
		}
	}

}

func (p DistributedExecutor) collectStage(job *falco.Job, ch *amqp.Channel,
	writer *falco.ResultCollector) error {
	acks, err := ch.Consume(
		job.Context.Name(), // queue
		"",                 // consumer
		true,               // auto-ack
		false,              // exclusive
		false,              // no-local
		false,              // no-wait
		nil,                // args
	)

	if err != nil {
		return err
	}

	for i := 0; i < len(job.Submitted); i++ {
		select {
		case x:=<-acks:
			msg := string(x.Body)
			parts := strings.Split(msg,",")
			ids := parts[0]
			state := parts[1] == "0"
			job.Submitted[ids].Done()
			if state {
				job.Submitted[ids].SetError(fmt.Errorf("runtime error"))
			}
			job.Done()
		case <-job.Canceled():
			fmt.Println("job got canceled")
		}
	}

	return nil
}


func (p DistributedExecutor) observeJobs(job *falco.Job,cmd falco.Submittable, writer *falco.ResultCollector) {
	for {
		select {
		case <-time.After(p.TestInterval):
			stranglers,failiures,compleated := p.selectStranglers(job)
			if compleated == len(job.Submitted){
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
					job.Info(fmt.Sprintf("%s\n",stranglers[i].ID))
					job.Done()
				}
				submitJobAsync(cmd, stranglers, job, nil)
			}
			for _, payload := range failiures {
				if !payload.IsCompleted(){
					job.Done()
					payload.SetError(fmt.Errorf("task timeout after %d tries",payload.GetNumberOfSubmissions()))
					payload.Done()

					payload.WriteError(writer)

				}
			}

		case <-job.Canceled():
			return
		}
	}
}

func (p DistributedExecutor) selectStranglers(job *falco.Job) ([]falco.InvocationPayload, []falco.InvocationPayload, int) {
	return p.Strategy.selectStranglers(job,p)
}