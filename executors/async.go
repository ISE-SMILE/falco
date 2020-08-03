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
	"runtime"
	"sync"
	"time"
)

type AsyncExecutor struct {
	Timeout time.Duration
}

func (p AsyncExecutor) Execute(job *falco.Job, submittable falco.Submittable, collector *falco.ResultCollector)  error {

	activations := make(chan map[string]interface{}, len(job.Tasks))
	start := time.Now()

	go func() {
		time.Sleep(1000 * time.Millisecond)
		err := submittable.Collect(job,activations,collector) //(job, activations, writer)
		if err != nil {
			fmt.Printf("%+v\n", err)
		}
	}()

	job.Info(fmt.Sprintf("submitting %d jobs\n", len(job.Tasks)))

	submitJobAsync(submittable, job.Tasks,job, activations)

	job.Info(fmt.Sprintf("submitted %d jobs", len(job.Tasks)))

	close(activations)

	if p.Timeout > 0 {
		if job.WithTimeout(p.Timeout) != nil {
			job.Cancel()
			//grace-period to finish up writes
			time.Sleep(500 * time.Millisecond)
			return fmt.Errorf("invoke timed out ...\n")
		}
	} else {
		job.Wait()
	}

	fmt.Printf("invocation done in %+v\n", time.Now().Sub(start))
	return nil

}

//submit jobs async and waits until all are submitted; adds invoc results to a chan
func submitJobAsync(submittable falco.Submittable, payloads []falco.InvocationPayload, job *falco.Job, activations chan map[string]interface{}) {
	threads := runtime.NumCPU()
	chunkSize := (len(payloads) + threads - 1) / threads

	var sendGroup sync.WaitGroup

	for i := 0; i < len(payloads); i += chunkSize {
		end := i + chunkSize

		if end > len(payloads) {
			end = len(payloads)
		}
		sendGroup.Add(1)

		payloadSlice := payloads[i:end]
		go func(payloads []falco.InvocationPayload, waitGroup *sync.WaitGroup) {
			for _, payload := range payloads {
				err := submittable.Submit(job, payload, activations)
				if err != nil {
					job.Info(fmt.Sprintf("invocation error: %+v\n", err))
				}
			}
			sendGroup.Done()
		}(payloadSlice, &sendGroup)
	}

	sendGroup.Wait()
}