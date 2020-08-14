/*
 * MIT License
 *
 * Copyright (c) 2020 Sebastian Werner
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

package executors

import (
	"encoding/json"
	"fmt"
	"github.com/ISE-SMILE/falco"
	"go.uber.org/atomic"
	"strings"
	"testing"
	"time"
)

type MockSubmittable struct {
	t     *testing.T
	queue *MockQueue
	delay time.Duration

	Submitted   *atomic.Int32
	Resubmitted *atomic.Int32
}

func NewMockSubmittable(t *testing.T, delay time.Duration, queue *MockQueue) *MockSubmittable {
	return &MockSubmittable{
		t: t, queue: queue, delay: delay, Submitted: atomic.NewInt32(0), Resubmitted: atomic.NewInt32(0),
	}
}
func (m MockSubmittable) Deploy(deployable falco.Deployable) (falco.Deployment, error) {
	m.t.Fatal("DistributedExecutor should not call Deploy at any time")
	return nil, nil
}

func (m MockSubmittable) Remove(deployment falco.Deployment) error {
	m.t.Fatal("DistributedExecutor should not call Remove at any time")
	return nil
}

func (m MockSubmittable) Scale(deployment falco.Deployment, options ...falco.ScaleOptions) (falco.Deployment, error) {
	m.t.Fatal("DistributedExecutor should not call Scale at any time")
	return nil, nil
}

func (m MockSubmittable) Invoke(deployment falco.Deployment, payload falco.InvocationPayload, collector falco.ResultCollector) error {
	m.t.Fatal("DistributedExecutor should not call Invoke at any time")
	return nil
}

func (m MockSubmittable) Submit(job *falco.Job, payload falco.InvocationPayload, c chan<- map[string]interface{}, options ...falco.InvocableOptions) error {
	job.SubmittedTask(payload)
	//part of the contract

	payload.Submitted()

	m.Submitted.Inc()
	if payload.GetNumberOfSubmissions() > 1 {
		m.Resubmitted.Inc()
	}

	go func() {
		var delay time.Duration
		var succede bool
		if val, ok := payload.(*falco.MockInvocation); ok {
			delay = m.delay + val.Delay
			succede = val.Succeed()
		} else {
			delay = m.delay
			succede = true
		}
		if succede {
			<-time.After(delay)
			mes := make(falco.Measurement)
			mes.SetJobID(job.Name())
			mes.SetInvocationID(payload.ID())
			m.queue.Add(job.Name(), mes)
			if payload.GetNumberOfSubmissions() == 1 {
				fmt.Print("+")
			} else {
				fmt.Print("@")
			}

		}

	}()
	<-time.After(100 * time.Millisecond)
	return nil
}

func (m MockSubmittable) Collect(job *falco.Job, i <-chan map[string]interface{}, collector falco.ResultCollector, options ...falco.InvocableOptions) error {
	return nil
}

type MockQueue struct {
	acks   chan MockMessage
	metics chan MockMessage
}

type MockMessage struct {
	body []byte
}

func (m MockMessage) Body() []byte {
	return m.body
}

func FromMeasurement(measurement falco.Measurement) MockMessage {
	data, err := json.Marshal(measurement)
	if err != nil {
		panic(err)
	}

	return MockMessage{
		body: data,
	}
}

func (m *MockQueue) Add(jobName string, measurement falco.Measurement) {

	m.metics <- FromMeasurement(measurement)

}

func (m *MockQueue) Setup(c *falco.Context) error {

	m.Open("any")
	return nil
}

func (m *MockQueue) Connect() error {
	return nil
}

func (m *MockQueue) Close() error {
	return nil
}

func (m *MockQueue) Open(s string) error {
	m.metics = make(chan MockMessage)
	m.acks = make(chan MockMessage)
	return nil
}

func (m *MockQueue) Purge(s string) error {
	m.Open(s)
	return nil
}

func (m *MockQueue) Delete(s string) error {
	m.Open("any")
	return nil
}

func (m *MockQueue) Consume(s string) (<-chan DEQueueMessage, error) {
	out := make(chan DEQueueMessage)

	var queue chan MockMessage
	if strings.HasSuffix(s, "-metrics") {
		queue = m.metics
	} else {
		queue = m.acks
	}
	go func(in chan MockMessage) {
		for {
			select {
			case d := <-in:
				out <- d
			}
		}
	}(queue)
	return out, nil
}
