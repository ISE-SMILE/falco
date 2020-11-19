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

type ExecutionPlan interface {

	//Integrated Deployable

	Phase() AsyncInvocationPhase

	//TODO: implement interface to allow for shuffle/fan-in/fan-out/merge operations after each phase - followup task output of a phase needs to be known, e.g., part of the AsyncInvocationPhase struct.

	NextPhase() *ExecutionPlan

	Deploy(platform AsyncPlatform)
	Remove(platform AsyncPlatform)
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
	//This method will block until all phases are done or a phase encountered an error.
	Execute(strategy ExecutionStrategy, platform AsyncPlatform) error

	Deploy(platform AsyncPlatform)
	Remove(platform AsyncPlatform)

	ProgressMonitor
}
