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

type InvocationPayload interface {
	//uniuqe task id (can be used to assosiate returned invocations to submitted invocations)
	ID() string
	//the time this payload was send
	SubmittedAt() time.Time
	//the latancy between the sumitted time and the time Done was called
	Latancy() time.Duration

	//if this payload is processed, e.g. we know it failed, or we have a result
	IsCompleted() bool
	//any error that occured with this paylaod
	Error() error
	//sets stubmission time and counts the number or resubmissions
	Submitted() int8
	//retuns the number of sumissions to a platfrom
	GetNumberOfSubmissions() int8
	//sets an error
	SetError(err error)

	//the runitme used to generate this invocation
	Runtime() Runtime
	//Set compleated to true and stores compleation time
	Done()

	//writer.Add(payload.Runtime().MakeFailure(payload.ID(),payload.Error().Error(),payload.SubmittedAt()))
	WriteError(writer *ResultCollector)


}

type Deployable interface {
	Payload() string
	Context() *Context
	Runtime() string
}

type Deployment interface {
	ID() string
}

type ScaleOptions func (deployment Deployment)

type Context struct {
	name string
	options map[string]interface{}
}

func NewContext(name string) *Context {
	return &Context{name: name}
}


func (r *Context) Name() string{
	return r.name
}

func (r *Context) add(name string, value interface{}){
	r.options[name] = value
}

func (r *Context) IsSet(name string) bool {
	_,ok := r.options[name];
	return ok
}

func (r *Context) String(name,defaultValue string) string {
	if val,ok := r.options[name]; ok {
		if value,ok := val.(string);ok {
			return value
		}
	}
	return defaultValue
}

func (r *Context) Int(name string,defaultValue int) int {
	if val,ok := r.options[name]; ok {
		if value,ok := val.(int);ok {
			return value
		}
	}
	return defaultValue
}

func (r *Context) Duration(name string,defaultValue time.Duration) time.Duration {
	if val,ok := r.options[name]; ok {
		if value,ok := val.( time.Duration);ok {
			return value
		}
	}
	return defaultValue
}

func (r *Context) Slice(name string) []string {
	if val,ok := r.options[name]; ok {
		if value,ok := val.([]string);ok {
			return value
		}
	}
	return []string{}
}

func (r *Context) Bool(name string) bool {
	if val,ok := r.options[name]; ok {
		if value,ok := val.(bool);ok {
			return value
		}
	}
	return false
}

func (r *Context) ToMap() map[string]string {
	opts := make(map[string]string)
	for k, i := range r.options {
		if val,ok := i.(string);ok{
			opts[k] = val
		}
	}
	return opts
}

func (r *Context) PrefixMap(prefix string) map[string]string {
	opts := make(map[string]string)
	for k, i := range r.options {
		if strings.HasPrefix(k,prefix) {
			if val, ok := i.(string); ok {
				opts[k] = val
			}
		}
	}
	return opts
}


func (r *Context) NewStingOption(name,value string){
	r.add(name,value)
}
func (r *Context) NewIntOption(name string,value int){
	r.add(name,value)
}
func (r *Context) NewDurationOption(name string,value time.Duration){
	r.add(name,value)
}
func (r *Context) NewSliceOption(name string,value []string){
	r.add(name,value)
}
func (r *Context) NewBoolOption(name string,value bool){
	r.add(name,value)
}


type InvocableOptions interface {
	Apply()
}