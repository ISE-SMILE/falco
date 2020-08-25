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
	"context"
	"fmt"
	"github.com/ISE-SMILE/falco"
	"testing"
	"time"
)

type NoOpStrategy struct {
}

func (n *NoOpStrategy) SelectStranglers(job *falco.Job, p *DistributedExecutor) ([]falco.InvocationPayload, []falco.InvocationPayload, int) {
	stranglers := make([]falco.InvocationPayload, 0)
	failures := make([]falco.InvocationPayload, 0)
	completed := 0
	for _, i := range job.Tasks {
		if i.IsCompleted() {
			completed++
		}
	}
	return stranglers, failures, completed
}

func TestDistributedExecutor_NoResubmitt(t *testing.T) {
	queue := &MockQueue{}
	queue.Setup(nil)
	executor := DistributedExecutor{
		Queue:        queue,
		TestInterval: time.Millisecond * 200,
		Strategy:     &NoOpStrategy{},
		Timeout:      time.Minute * 10,
	}

	mockSubmittable := NewMockSubmittable(t, time.Millisecond*5, queue)

	ctx := context.Background()
	tasks := make([]falco.InvocationPayload, 0)

	var invocations int32 = 1000
	var i int32 = 0
	for ; i < invocations; i++ {
		tasks = append(tasks, &falco.MockInvocation{IID: fmt.Sprintf("t%d", i)})
	}

	job := falco.NewJob(ctx, tasks, 15, falco.Monitor{})

	writer := &falco.MockWriter{}
	go func() {
		for {
			<-time.After(1 * time.Second)
			fmt.Print("|")
		}
	}()
	err := executor.Execute(job, mockSubmittable, writer)
	if err != nil {
		t.Fatal("executor failed ;(")
	}
	if mockSubmittable.Submitted.Load() < invocations {
		t.Logf("expected %d invocations only submitted %d", invocations, mockSubmittable.Submitted.Load())
		t.Fail()
	}
	if mockSubmittable.Resubmitted.Load() > 0 {
		t.Logf("expected 0 resubmissions got %d", mockSubmittable.Resubmitted.Load())
		t.Fail()
	}
}

func TestDistributedExecutor_DeadlineResubmit(t *testing.T) {
	queue := &MockQueue{}
	queue.Setup(nil)
	executor := DistributedExecutor{
		Queue:        queue,
		TestInterval: time.Millisecond * 100,
		Strategy: &DeadlineStragglerStrategy{
			DeadlineDuration: time.Millisecond * 200,
			ReTryThreshold:   2,
		},
		Timeout: time.Minute * 5,
	}

	mockSubmittable := NewMockSubmittable(t, time.Millisecond*5, queue)

	ctx := context.Background()
	tasks := make([]falco.InvocationPayload, 0)

	var invocations int32 = 100
	var i int32 = 0
	for ; i < invocations; i++ {
		tasks = append(tasks, &falco.MockInvocation{IID: fmt.Sprintf("t%d", i), Tries: 0})
	}

	job := falco.NewJob(ctx, tasks, 15, falco.Monitor{})

	writer := &falco.MockWriter{}
	go func() {
		for {
			<-time.After(1 * time.Second)
			fmt.Print("|")
		}
	}()
	err := executor.Execute(job, mockSubmittable, writer)
	if err != nil {
		t.Fatal("executor failed ;(")
	}
	if mockSubmittable.Submitted.Load() < invocations {
		t.Logf("expected %d invocations only submitted %d", invocations, mockSubmittable.Submitted.Load())
		t.Fail()
	}
	if mockSubmittable.Resubmitted.Load() > 0 {
		t.Logf("expected 0 resubmissions got %d - total submissiosn %d", mockSubmittable.Resubmitted.Load(), mockSubmittable.Submitted.Load())
		for _, i := range job.Tasks {
			fmt.Printf("%+v\n", i)
		}
		t.Fail()
	}
}

func TestDistributedExecutor_DeadlineResubmit_withStragglers(t *testing.T) {
	queue := &MockQueue{}
	queue.Setup(nil)
	executor := DistributedExecutor{
		Queue:        queue,
		TestInterval: time.Millisecond * 50,
		Strategy: &DeadlineStragglerStrategy{
			DeadlineDuration: time.Millisecond * 200,
			ReTryThreshold:   2,
		},
		Timeout: time.Minute * 5,
	}

	mockSubmittable := NewMockSubmittable(t, time.Millisecond*100, queue)

	ctx := context.Background()
	tasks := make([]falco.InvocationPayload, 0)

	var invocations int32 = 100
	var i int32 = 0
	for ; i < invocations; i++ {
		if i%10 == 0 {
			tasks = append(tasks, &falco.MockInvocation{IID: fmt.Sprintf("t%d", i), Tries: 0, Delay: time.Millisecond * 200})
		} else {
			tasks = append(tasks, &falco.MockInvocation{IID: fmt.Sprintf("t%d", i), Tries: 0})

		}
	}

	job := falco.NewJob(ctx, tasks, 15, falco.Monitor{})

	writer := &falco.MockWriter{}
	go func() {
		for {
			<-time.After(1 * time.Second)
			fmt.Print("|")
		}
	}()
	err := executor.Execute(job, mockSubmittable, writer)
	if err != nil {
		t.Fatal("executor failed ;(")
	}
	if mockSubmittable.Submitted.Load() < invocations {
		t.Logf("expected %d invocations only submitted %d", invocations, mockSubmittable.Submitted.Load())
		t.Fail()
	}
	if mockSubmittable.Resubmitted.Load() > invocations/10 {
		t.Logf("expected 0 resubmissions got %d - total submissiosn %d", mockSubmittable.Resubmitted.Load(), mockSubmittable.Submitted.Load())
		for _, i := range job.Tasks {
			fmt.Printf("%+v\n", i)
		}
		t.Fail()
	}
}

func TestDistributedExecutor_MeanExecTime_withStragglers(t *testing.T) {
	queue := &MockQueue{}
	queue.Setup(nil)

	minimumSamplingSize := float32(0.4)

	executor := DistributedExecutor{
		Queue:        queue,
		TestInterval: time.Millisecond * 50,
		Strategy: &MeanBackoffStragglerStrategy{
			ReTryThreshold:    2,
			MinimumSampleSize: &minimumSamplingSize,
			Graceperiod:       time.Millisecond * 50,
		},
		Timeout: time.Minute * 5,
	}

	mockSubmittable := NewMockSubmittable(t, time.Millisecond*100, queue)

	ctx := context.Background()
	tasks := make([]falco.InvocationPayload, 0)

	var invocations int32 = 100
	var i int32 = 0
	for ; i < invocations; i++ {
		if i%10 == 0 {
			tasks = append(tasks, &falco.MockInvocation{IID: fmt.Sprintf("t%d", i), Tries: 0, Delay: time.Millisecond * 200})
		} else {
			tasks = append(tasks, &falco.MockInvocation{IID: fmt.Sprintf("t%d", i), Tries: 0})

		}
	}

	job := falco.NewJob(ctx, tasks, 15, falco.Monitor{})

	writer := &falco.MockWriter{}
	go func() {
		for {
			<-time.After(1 * time.Second)
			fmt.Print("|")
		}
	}()
	err := executor.Execute(job, mockSubmittable, writer)
	if err != nil {
		t.Fatal("executor failed ;(")
	}
	if mockSubmittable.Submitted.Load() < invocations {
		t.Logf("expected %d invocations only submitted %d", invocations, mockSubmittable.Submitted.Load())
		t.Fail()
	}
	if mockSubmittable.Resubmitted.Load() > invocations/10 {
		t.Logf("expected 0 resubmissions got %d - total submissiosn %d", mockSubmittable.Resubmitted.Load(), mockSubmittable.Submitted.Load())
		for _, i := range job.Tasks {
			fmt.Printf("%+v\n", i)
		}
		t.Fail()
	}
}
