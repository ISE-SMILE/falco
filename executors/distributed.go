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
	"net/url"
	"os"
	"os/signal"
	"strings"
	"time"
)

type StragglerStrategy interface {
	SelectStranglers(job *falco.Job, p DistributedExecutor) ([]falco.InvocationPayload, []falco.InvocationPayload, int)
}

type DEQueueMessage interface {
	Body() []byte
}

type DEQueue interface {
	Setup(*falco.Context) error
	Connect() error
	Close() error
	Open(string) error
	Purge(string) error
	Delete(string) error
	Consume(string) (<-chan DEQueueMessage, error)
}

type DeadlineStragglerStrategy struct {
	DeadlineDuration time.Duration
	ReTryThreshold   int8
}

func (d DeadlineStragglerStrategy) SelectStranglers(job *falco.Job, p DistributedExecutor) ([]falco.InvocationPayload, []falco.InvocationPayload, int) {
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

func (m MeanBackoffStragglerStrategy) SelectStranglers(job *falco.Job, p DistributedExecutor) ([]falco.InvocationPayload, []falco.InvocationPayload, int) {
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

func (p DistributedExecutor) Execute(job *falco.Job, submittable falco.Submittable, writer falco.ResultCollector) error {

	err := p.Queue.Connect()
	if err != nil {
		return err
	}

	defer p.Queue.Close()

	//create the rabbitmq queues
	//create control-plane
	controlQueueName := job.Name()
	err = p.Queue.Open(controlQueueName)
	if err != nil {
		return err
	}
	//create metrics-plane
	metricsQueueName := fmt.Sprintf("%s-metrics", job.Name())
	err = p.Queue.Open(metricsQueueName)
	if err != nil {
		return err
	}

	//remove content of privious runs?
	_ = p.Queue.Purge(controlQueueName)
	_ = p.Queue.Purge(metricsQueueName)

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
			err = p.collectMetrics(job, metricsQueueName, writer)
		} else {
			err = p.collectStage(job, controlQueueName, writer)
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
	//cleanup
	_ = p.Queue.Delete(controlQueueName)
	_ = p.Queue.Delete(metricsQueueName)

	job.PrintStats()

	return err
}

func (p DistributedExecutor) collectMetrics(job *falco.Job, queueName string,
	writer falco.ResultCollector) error {
	metrics, err := p.Queue.Consume(queueName)

	if err != nil {
		return err
	}
	start := time.Now()
	for {
		select {
		case m := <-metrics:
			var data falco.Measurement
			err = json.Unmarshal(m.Body(), &data)

			if data != nil {
				//TODO:!
				//data.withDefaults()
				payloadID := data.InvocationID()
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

func (p DistributedExecutor) collectStage(job *falco.Job, queueName string,
	writer falco.ResultCollector) error {
	acks, err := p.Queue.Consume(queueName)

	if err != nil {
		return err
	}

	for i := 0; i < len(job.Tasks); i++ {
		select {
		case x := <-acks:
			msg := string(x.Body())
			parts := strings.Split(msg, ",")
			ids := parts[0]
			state := parts[1] == "0"
			if payload, err := job.PayloadFromId(ids); err == nil {
				payload.Done()
				if state {
					payload.SetError(fmt.Errorf("runtime error"))
				}
			}

			job.Done(ids)
		case <-job.Canceled():
			fmt.Println("job got canceled")
		}
	}

	return nil
}

func (p DistributedExecutor) observeJobs(job *falco.Job, cmd falco.Submittable, writer falco.ResultCollector) {
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

func (p DistributedExecutor) selectStranglers(job *falco.Job) ([]falco.InvocationPayload, []falco.InvocationPayload, int) {
	return p.Strategy.SelectStranglers(job, p)
}

//RabbitMQWrapper

type RabbitMQWrapper struct {
	QueueConnection *amqp.Connection
	Channel         *amqp.Channel
	Queues          map[string]amqp.Queue
}

type rabbidmqMessage struct {
	d amqp.Delivery
}

func (r rabbidmqMessage) Body() []byte {
	return r.d.Body
}

func FromDelivery(d amqp.Delivery) *rabbidmqMessage {
	return &rabbidmqMessage{d}
}

//Setup the following values must be set in the context:
// rmquser - username of rabidmq (default guest)
// rmqpass - password of rabidmq user (default guest)
// rmq - address (ip or hostname) for rabidmq (default localhost)
// rmqport - port for rabidmq (default 5672)
func (r *RabbitMQWrapper) Setup(c *falco.Context) error {
	rmqURL := fmt.Sprintf("amqp://%s:%s@%s:%d/",
		url.QueryEscape(c.String("rmquser", "guest")),
		url.QueryEscape(c.String("rmqpass", "guest")),
		c.String("rmq", "localhost"),
		c.Int("rmqport", 5672),
	)

	conn, err := amqp.Dial(rmqURL)
	if err != nil {
		return err
	}
	r.QueueConnection = conn

	return nil
}

func (r *RabbitMQWrapper) Connect() error {
	ch, err := r.QueueConnection.Channel()

	if err != nil {
		return err
	}

	r.Channel = ch
	return nil
}

func (r *RabbitMQWrapper) Close() error {
	_ = r.Channel.Close()
	return r.QueueConnection.Close()
}

func (r *RabbitMQWrapper) Delete(name string) error {
	_, err := r.Channel.QueueDelete(name, true, true, true)
	return err
}

func (r *RabbitMQWrapper) Open(name string) error {
	if !r.QueueConnection.IsClosed() {
		if _, ok := r.Queues[name]; !ok {
			queue, err := r.Channel.QueueDeclare(name, false, false, false, false, nil)
			if err != nil {
				return err
			}

			r.Queues[name] = queue
		}

		return nil
	} else {
		return fmt.Errorf("queue connection is closed")
	}
}

func (r *RabbitMQWrapper) Purge(name string) error {
	if !r.QueueConnection.IsClosed() {
		_, err := r.Channel.QueuePurge(name, true)
		return err
	} else {
		return fmt.Errorf("queue connection is closed")
	}
}

func (r *RabbitMQWrapper) Consume(name string) (<-chan DEQueueMessage, error) {
	out := make(chan DEQueueMessage)
	messages, err := r.Channel.Consume(
		name,  // queue
		"",    // consumer
		true,  // auto-ack
		false, // exclusive
		false, // no-local
		false, // no-wait
		nil,   // args
	)
	if err != nil {
		return nil, err
	}

	go func() {
		for {
			select {
			case d := <-messages:
				out <- FromDelivery(d)
			}
		}
	}()

	return out, nil
}
