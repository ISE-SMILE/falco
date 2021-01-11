/*
 * MIT License
 *
 * Copyright (c) 2021 Sebastian Werner
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

package falco

import "time"

type StringDeployable struct {
	payload string
	runtime Runtime
}

func (ed StringDeployable) Payload() interface{} {
	return ed.payload
}
func (ed StringDeployable) Option() *Options {
	return &Options{
		name:    "",
		options: make(map[string]interface{}),
	}
}
func (ed StringDeployable) Runtime() Runtime {
	return ed.runtime
}

func NewStringDeployable(payload string, runtime Runtime) Deployable {
	return &StringDeployable{
		payload: payload,
		runtime: runtime,
	}
}

func NewSimpleInvocation(id string, runtime Runtime) Invocation {
	return &SimpleInvocation{
		id:      id,
		runtime: runtime,
	}
}

type SimpleInvocation struct {
	id               string
	submittedAt      time.Time
	duration         time.Duration
	result           interface{}
	runtimeReference interface{}
	err              error
	runtime          Runtime
}

func (s SimpleInvocation) InvocationID() string {
	return s.id
}

func (s SimpleInvocation) SubmittedAt() time.Time {
	return s.submittedAt
}

func (s SimpleInvocation) InvocationDuration() time.Duration {
	return s.duration
}

func (s SimpleInvocation) IsCompleted() bool {
	return s.result != nil || s.err != nil
}

func (s SimpleInvocation) Error() error {
	return s.err
}

func (s SimpleInvocation) Submitted() int8 {
	s.submittedAt = time.Now()
	return 1
}

func (s SimpleInvocation) GetNumberOfSubmissions() int8 {
	return 1
}

func (s *SimpleInvocation) SetError(err error) {
	s.err = err
}

func (s SimpleInvocation) Runtime() Runtime {
	return s.runtime
}

func (s *SimpleInvocation) Done(duration *time.Duration) {
	if duration != nil {
		s.duration = *duration
	} else {
		s.duration = time.Now().Sub(s.submittedAt)
	}

}

func (s SimpleInvocation) MarkAsResubmitted() {
	s.submittedAt = time.Time{}
}

func (s *SimpleInvocation) SetResult(result interface{}) {
	s.result = result
}

func (s *SimpleInvocation) Result() interface{} {
	return s.result
}

func (s SimpleInvocation) SetRuntimeReference(id interface{}) {
	s.runtimeReference = id
}

func (s SimpleInvocation) RuntimeReference() interface{} {
	return s.runtimeReference
}
