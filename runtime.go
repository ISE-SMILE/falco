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
	"time"
)

type Measurable interface {
	//XXX: these I don't like
	MakeFailure(id, cause string, start time.Time) Measurement
	MakeMeasurement(map[string]interface{}) Measurement
}

type InvocationStrategy interface {
	//short name for the strategy
	StrategyName() string
	//short discription used in ui elementes and logging
	StrategyUsage() string
	//this method should generate the invocation payload that
	InvocationPayload(context *Context, workdir string, files ...string) ([]InvocationPayload, error)
}

type Runtime interface {
	//compile a set of given files to a deployment package that can be deployed to any platfrom
	MakeDeployment(*Context, ...string) (Deployable, error)

	//
	InvocationStrategies() []InvocationStrategy

	//used default invocation strategy for this runtime
	InvocationPayload(context *Context, workdir string, files ...string) ([]InvocationPayload, error)

	Measurable
}
