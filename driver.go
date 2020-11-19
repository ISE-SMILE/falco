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

type ProgressMonitor interface {
	Setup()
	Advance(int)
	Expand(int)
	Render()
	Finish()
	Info(string)
}

/**
Interface to drive complex serverless applications that execute multiple invocations or ExecutionPlan.
*/
type Driver interface {

	//Runtime() the runtime used by this driver
	Runtime() Runtime

	//Strategies() a set of availible strategies by this driver
	Strategies() []ExecutionStrategy

	//ExecutionPlan() set of phases this driver needs to execute
	ExecutionPlan() *ExecutionPlan

	//Execute starts the execution of the ExecutionPlan using the specified ExecutionStrategy on the specified runtime.
	//This method will block until all phases are done or a Phase encountered an error.
	Execute(strategy ExecutionStrategy, platform AsyncPlatform) error

	Deploy(platform AsyncPlatform)
	Remove(platform AsyncPlatform)

	ProgressMonitor
}

//XXX: longterm - this should be a DAG instead of a List, there are pob. Phases that can run in parallel ;) but for now we assume full phase interdependencies
type ExecutionPlan struct {
	Deployable Deployable
	Phase      *AsyncInvocationPhase

	//TODO: implement interface to allow for shuffle/fan-in/fan-out/merge operations after each Phase - followup task output of a Phase needs to be known, e.g., part of the AsyncInvocationPhase struct.

	next       *ExecutionPlan
	deployment Deployment
}

func NewExecutionPlan(dep Deployable, task *AsyncInvocationPhase) *ExecutionPlan {
	return &ExecutionPlan{
		Deployable: dep,
		Phase:      task,
		next:       nil,
		deployment: nil,
	}
}

func (e *ExecutionPlan) set(next *ExecutionPlan) {
	e.next = next
}

func (e *ExecutionPlan) last() *ExecutionPlan {
	for curr := e.next; curr != nil; curr = curr.next {
		if curr.next == nil {
			return curr
		}
	}
	return e

}
func (e *ExecutionPlan) Append(plan *ExecutionPlan) {
	e.last().set(plan)
}

func (e *ExecutionPlan) ListRemaining() []*ExecutionPlan {
	remaining := make([]*ExecutionPlan, 0)

	for curr := e.next; curr != nil; curr = curr.next {
		remaining = append(remaining, curr)
	}

	return remaining
}

func (e *ExecutionPlan) Next() *ExecutionPlan {
	return e.next
}

func (e *ExecutionPlan) Deploy(platform AsyncPlatform) (Deployment, error) {
	dep, err := platform.Deploy(e.Deployable)
	if err != nil {
		e.deployment = dep
	}
	return dep, err
}

func (e *ExecutionPlan) Remove(platform AsyncPlatform) error {
	if e.deployment != nil {
		return platform.Remove(e.deployment)
	}
	return nil
}
