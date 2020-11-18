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
	"fmt"
	"github.com/ISE-SMILE/falco"
)

type ParallelExecutor struct {
	Threads int
}

func (o ParallelExecutor) Execute(job *falco.AsyncObserver, submittable falco.AsyncPlatform) error {
	queue := make(chan falco.Invocation, len(job.Payloads))

	results := make(chan error)

	worker := func(queue chan falco.Invocation, returns chan error) {
		var counter = 0
		for payload := range queue {
			_, err := submittable.Invoke(job.Deployment, payload)

			counter += 1
			returns <- err
		}
		fmt.Printf("processed requests %d \n", counter)
	}

	for _, p := range job.Payloads {
		queue <- p
	}

	for i := 0; i < o.Threads; i++ {
		go worker(queue, results)
	}
	close(queue)
	for i := 0; i < len(job.Payloads); i++ {
		<-results
	}
	return nil
}
