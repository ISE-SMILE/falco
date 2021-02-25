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
	"strings"
	"time"
)

//Invocation represents a single call to a FaaS function, capturing the state of this invocation.
type Invocation interface {
	//InvocationID unique task IID (can be used to associate returned invocations to submitted invocations)
	InvocationID() string
	//SubmittedAt the time this payload was send
	SubmittedAt() time.Time
	//InvocationDuration the Duration between the submitted time and the time Done was called
	InvocationDuration() time.Duration

	//IsCompleted if this payload is processed, e.g. we know it failed, or we have a result
	IsCompleted() bool
	//Error any error that occurred with this payload
	Error() error
	//Submitted sets submission time and counts the number or resubmissions
	Submitted() int8
	//GetNumberOfSubmissions returns the number of invocations to a platform
	GetNumberOfSubmissions() int8
	//SetError sets an error
	SetError(err error)

	//Runtime the runtime used to generate this invocation
	Runtime() Runtime
	//Done Set completed to true and stores completion time, calculates the duration using time.Now() if duration is nil
	Done(duration *time.Duration)

	//MarkAsResubmitted is called if a task gets resubmitted (due to error or because it seamed to straggle)
	MarkAsResubmitted()

	//SetResult can be used to set a result for each activation
	SetResult(result interface{})

	//Result returns data set with SetResult
	Result() interface{}

	//SetRuntimeReference for registering runtime identifier, like, activation-id
	SetRuntimeReference(id interface{})

	//RuntimeReference set with SetRuntimeReference
	RuntimeReference() interface{}
}

//Deployable is the interfaced used for Platform and AsyncPlatform to deploy a Function
type Deployable interface {
	Payload() interface{}
	Option() *Options
	Runtime() Runtime
}

//Each Platform or AsyncPlatform will return a reference to a deploy function using this interface.
type Deployment interface {
	DeploymentID() string
}

type ScaleOptions func(deployment Deployment)

type Options struct {
	name    string
	options map[string]interface{}
}

func NewFacloOptions(name string) *Options {
	return &Options{name: name, options: make(map[string]interface{})}
}

func (r *Options) Name() string {
	return r.name
}

func (r *Options) add(key string, value interface{}) {
	r.options[key] = value
}

func (r *Options) IsSet(name string) bool {
	_, ok := r.options[name]
	return ok
}

func (r *Options) String(name, defaultValue string) string {
	if val, ok := r.options[name]; ok {
		if value, ok := val.(string); ok {
			return value
		}
	}
	return defaultValue
}

func (r *Options) Int(name string, defaultValue int) int {
	if val, ok := r.options[name]; ok {
		if value, ok := val.(int); ok {
			return value
		}
	}
	return defaultValue
}

func (r *Options) Duration(name string, defaultValue time.Duration) time.Duration {
	if val, ok := r.options[name]; ok {
		if value, ok := val.(time.Duration); ok {
			return value
		}
	}
	return defaultValue
}

func (r *Options) Slice(name string) []string {
	if val, ok := r.options[name]; ok {
		if value, ok := val.([]string); ok {
			return value
		}
	}
	return []string{}
}

func (r *Options) Bool(name string) bool {
	if val, ok := r.options[name]; ok {
		if value, ok := val.(bool); ok {
			return value
		}
	}
	return false
}

func (r *Options) ToMap() map[string]string {
	opts := make(map[string]string)
	for k, i := range r.options {
		if val, ok := i.(string); ok {
			opts[k] = val
		}
	}
	return opts
}

func (r *Options) PrefixMap(prefix string) map[string]string {
	opts := make(map[string]string)
	for k, i := range r.options {
		if strings.HasPrefix(k, prefix) {
			if val, ok := i.(string); ok {
				opts[k] = val
			}
		}
	}
	return opts
}

func (r *Options) NewStingOption(name, value string) {
	r.add(name, value)
}
func (r *Options) NewIntOption(name string, value int) {
	r.add(name, value)
}
func (r *Options) NewDurationOption(name string, value time.Duration) {
	r.add(name, value)
}
func (r *Options) NewSliceOption(name string, value []string) {
	r.add(name, value)
}
func (r *Options) NewBoolOption(name string, value bool) {
	r.add(name, value)
}

type InvocableOptions interface {
	Apply()
}
