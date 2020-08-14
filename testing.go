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

package falco

import (
	"fmt"
	"time"
)

type Monitor struct {
}

func (m Monitor) Setup() {}

func (m Monitor) Advance(i int) {

}

func (m Monitor) Expand(i int) {}

func (m Monitor) Render() {}

func (m Monitor) Finish() {
	fmt.Println()
}

func (m Monitor) Info(s string) {
	//fmt.Fprintln(os.Stderr,s)
}

type MockWriter struct {
	data []Measurement
}

func (m *MockWriter) Add(measurement Measurement) {
	if m.data == nil {
		m.data = make([]Measurement, 0)
	}
	m.data = append(m.data, measurement)
}

func (m *MockWriter) Write(s string) error {
	return nil
}

func (m *MockWriter) Print() {
	for _, d := range m.data {
		fmt.Printf("%+v\n", d)
	}
}

type MockRuntime struct {
}

func (m *MockRuntime) MakeDeployment(c *Context, s ...string) (Deployable, error) {
	panic("implement me")
}

func (m *MockRuntime) InvocationPayload(c *Context, s ...string) ([]InvocationPayload, error) {
	panic("implement me")
}

func (m *MockRuntime) MakeFailure(id, cause string, start time.Time) Measurement {
	panic("implement me")
}

func (m *MockRuntime) MakeMeasurement(m2 map[string]interface{}) Measurement {
	panic("implement me")
}

type MockInvocation struct {
	IID             string
	SUB             time.Time
	COM             time.Time
	DONE            bool
	ERR             error
	Tries           int8
	Delay           time.Duration
	SuccessSelector func(invocation *MockInvocation) bool
}

func (m *MockInvocation) MarkAsResubmitted() {
	//NO-OP
}

func (m *MockInvocation) ID() string {
	return m.IID
}

func (m *MockInvocation) SubmittedAt() time.Time {
	return m.SUB
}

func (m *MockInvocation) Latancy() time.Duration {
	return m.COM.Sub(m.SUB)
}

func (m *MockInvocation) IsCompleted() bool {
	return m.DONE
}

func (m *MockInvocation) Error() error {
	return m.ERR
}

func (m *MockInvocation) Submitted() int8 {
	m.SUB = time.Now()
	m.Tries += 1
	return m.Tries
}

func (m *MockInvocation) GetNumberOfSubmissions() int8 {
	return m.Tries
}

func (m *MockInvocation) SetError(err error) {
	m.ERR = err
}

func (m *MockInvocation) Runtime() Runtime {
	return &MockRuntime{}
}

func (m *MockInvocation) Done() {
	m.COM = time.Now()
	m.DONE = true
}

func (m *MockInvocation) WriteError(writer ResultCollector) {}

func (m *MockInvocation) Succeed() bool {
	if m.SuccessSelector != nil {
		return m.SuccessSelector(m)
	}
	return true
}