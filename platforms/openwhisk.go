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

package platforms

import (
	"fmt"
	"github.com/ISE-SMILE/falco"
	"github.com/apache/openwhisk-client-go/whisk"
	"io/ioutil"
	"net/http"
	"runtime"
	"time"
)

type OpenWhisk struct {
	cli *whisk.Client

	Host    string
	Token   string
	Verbose bool

	BACKOFF  time.Duration
	maxRetry int
	threads  int
}

type OpenWhiskOption func(*OpenWhisk)

func WithHost(host string) OpenWhiskOption {
	return func(openWhisk *OpenWhisk) {
		openWhisk.Host = host
		err := openWhisk.connect()
		if err != nil {
			panic(err)
		}
	}
}

func WithAuthToken(token string) OpenWhiskOption {
	return func(openWhisk *OpenWhisk) {
		openWhisk.Token = token
		err := openWhisk.connect()
		if err != nil {
			panic(err)
		}
	}
}

func WithVerboseLogging() OpenWhiskOption {
	return func(openWhisk *OpenWhisk) {
		openWhisk.Verbose = true
	}
}

func ScaleMemory(memory int) falco.ScaleOptions {
	return func(deployment falco.Deployment) {
		if dep, ok := deployment.(OpenWhiskDeployment); ok {
			dep.Memory = memory
		}
	}
}

func NewOpenWhisk(options ...OpenWhiskOption) (*OpenWhisk, error) {
	base := &OpenWhisk{
		BACKOFF:  500 * time.Millisecond,
		maxRetry: 300,
		threads:  runtime.NumCPU(),
		Host:     "localhost",
	}

	for _, o := range options {
		o(base)
	}

	err := base.connect()
	if err != nil {
		return nil, err
	}

	return base, nil

}

type OpenWhiskDeployment struct {
	ActionName    string
	Memory        int
	action        *whisk.Action
	qualifiedName *QualifiedName
}

func (o OpenWhiskDeployment) ID() string {
	return o.ActionName
}

func ActionName() string {
	return StringWithCharset(12, charset)
}

func (ow *OpenWhisk) Deploy(deployable falco.Deployable) (falco.Deployment, error) {
	var qualifiedName = new(QualifiedName)
	deployment := OpenWhiskDeployment{
		ActionName: ActionName(),
	}
	var err error
	context := deployable.Context()

	if qualifiedName, err = NewQualifiedName(deployment.ActionName); err != nil {
		return nil, fmt.Errorf("failed to create a qualified name for %s cause:%v", deployment.ActionName, err)
	}

	action := new(whisk.Action)

	ow.cli.Namespace = qualifiedName.GetNamespace()
	action.Name = qualifiedName.GetEntityName()
	action.Namespace = qualifiedName.GetNamespace()

	env := context.PrefixMap("env")
	for k, v := range env {
		action.Parameters = action.Parameters.AddOrReplace(&whisk.KeyValue{
			Key:   k,
			Value: v,
		})
	}

	//WHY Go WHY!
	MemoryLimit := context.Int("memory", 192)
	deployment.Memory = MemoryLimit

	//TODO: do we want to make this context dependend?!
	action.Limits = &whisk.Limits{
		Timeout: nil,
		Memory:  &MemoryLimit,
		Logsize: nil,

		Concurrency: nil,
	}

	payload := deployable.Payload()
	runtimeIdentifier := deployable.Runtime()
	action.Exec = &whisk.Exec{
		Kind: runtimeIdentifier,
		Code: &payload,
	}
	action, _, err = ow.cli.Actions.Insert(action, true)
	deployment.action = action
	deployment.qualifiedName = qualifiedName
	return deployment, err
}

func (ow *OpenWhisk) Remove(deployment falco.Deployment) error {
	qualifiedName := ow.qualifiedName(deployment)
	if qualifiedName == nil {
		return fmt.Errorf("failed to create a qualified name for %s ", deployment.ID())
	}
	ow.cli.Namespace = qualifiedName.GetNamespace()

	_, err := ow.cli.Actions.Delete(qualifiedName.GetEntityName())
	return err
}

func (ow *OpenWhisk) qualifiedName(deployment falco.Deployment) *QualifiedName {
	whiskDeployment := deployment.(OpenWhiskDeployment)

	var qualifiedName *QualifiedName
	var err error

	if whiskDeployment.qualifiedName == nil {
		if qualifiedName, err = NewQualifiedName(whiskDeployment.ActionName); err != nil {
			return nil
		}
	} else {
		qualifiedName = whiskDeployment.qualifiedName
	}
	return qualifiedName
}

func (ow *OpenWhisk) Scale(deployment falco.Deployment, options ...falco.ScaleOptions) (falco.Deployment, error) {
	whiskDeployment := deployment.(OpenWhiskDeployment)
	qualifiedName := ow.qualifiedName(whiskDeployment)
	if qualifiedName == nil {
		return deployment, fmt.Errorf("failed to create a qualified name for %s cause", whiskDeployment.ActionName)
	}

	action, _, err := ow.cli.Actions.Get(whiskDeployment.ActionName, false)
	if err != nil {
		return deployment, err
	}

	for _, option := range options {
		option(whiskDeployment)
	}

	action.Limits.Memory = &whiskDeployment.Memory

	action, _, err = ow.cli.Actions.Insert(action, true)
	if err != nil {
		return deployment, err
	}
	whiskDeployment.action = action

	return whiskDeployment, nil
}

func (ow *OpenWhisk) Invoke(deployment falco.Deployment, payload falco.InvocationPayload, writer falco.ResultCollector) error {
	whiskDeployment := deployment.(OpenWhiskDeployment)
	qualifiedName := ow.qualifiedName(whiskDeployment)
	if qualifiedName == nil {
		return fmt.Errorf("failed to create a qualified name for %s cause", whiskDeployment.ActionName)
	}

	ow.cli.Namespace = qualifiedName.GetNamespace()
	start := time.Now()
	payload.Submitted()
	inv, resp, err := ow.cli.Actions.Invoke(
		qualifiedName.GetEntityName(),
		payload,
		true,
		true)
	elapsed := time.Since(start)

	if err != nil {
		return err
	}

	if writer != nil {
		var measurements falco.Measurement
		measurements = inv

		payload.Runtime().MakeMeasurement(measurements)

		writeMeasurement(measurements, payload.ID(), elapsed, writer)

		fmt.Printf("got %+v\n", measurements)
	}

	if writer == nil && ow.Verbose {
		data, _ := ioutil.ReadAll(resp.Body)
		fmt.Printf("got %s\n", string(data))
		//fmt.Printf("%+v", res)
	}

	return nil
}

func (ow *OpenWhisk) Submit(job *falco.Job, payload falco.InvocationPayload,
	activationQueue chan<- map[string]interface{}, options ...falco.InvocableOptions) error {

	whiskDeployment, ok := job.Deployment.(OpenWhiskDeployment)
	if !ok {
		return fmt.Errorf("job is not a Job not compatible with OpenWhisk")
	}

	job.TakeSpawn()

	qualifiedName := ow.qualifiedName(whiskDeployment)
	if qualifiedName == nil {
		return fmt.Errorf("failed to create a qualified name for %s cause", whiskDeployment.ActionName)
	}

	ow.cli.Namespace = qualifiedName.GetNamespace()
	inv, resp, err := ow.cli.Actions.Invoke(
		qualifiedName.GetEntityName(),
		payload,
		false,
		false)

	if err != nil {
		return err
	}
	if ow.Verbose {
		if id, ok := inv["activationId"]; ok {
			job.Info(fmt.Sprintf("%s\n", id))
		} else {
			job.Info(fmt.Sprintf("[%d] %s\n", resp.StatusCode, payload.ID))
		}
	}
	inv["fid"] = payload.ID()

	if activationQueue != nil {
		activationQueue <- inv
	}
	payload.Submitted()
	job.SubmittedTask(payload)
	time.Sleep(100 * time.Millisecond)

	return nil
}

func (ow *OpenWhisk) Collect(job *falco.Job, activations <-chan map[string]interface{}, writer falco.ResultCollector,
	options ...falco.InvocableOptions) error {
	threads := ow.threads
	pool := make(chan struct{}, threads)
	for {
		select {
		case activation, ok := <-activations:
			//block if to many request are currently pending
			if ok {
				pool <- struct{}{}
				go ow.fetchAsyncResult(job, pool, activation, writer)
			} else {
				time.Sleep(200 * time.Millisecond)
			}

		case <-job.Canceled():
			fmt.Printf("collection canceld with %d activations left\n", len(activations))
		}
	}
}

func (ow *OpenWhisk) fetchAsyncResult(job *falco.Job, pool chan struct{}, activation map[string]interface{}, writer falco.ResultCollector) {
	//give back the worker ticket
	defer func() { <-pool }()

	tries := 0

	var activationID string
	if id, ok := activation["activationId"]; ok {
		activationID = id.(string)
	} else {
		//XXX How did this happen?
		if ow.Verbose {
			fmt.Printf("unexpected state:%+v\n", activation)
		}
		return
	}

	name := ""
	if val, ok := activation["fid"]; ok && val != nil {
		name = val.(string)
	}
	//hint that this request was processed (or failed)
	defer job.Done(name)

	if ow.Verbose {
		job.Info(fmt.Sprintf("fetching %s\n", activationID))
	}

	for {
		tries += 1
		job.TakeQuery()
		//api call
		get, resp, err := ow.cli.Activations.Get(activationID)
		if err != nil || resp == nil {
			//if Verbose {
			//	fmt.Printf("failed to get %s due to %+v\n", activationID, err)
			//}

			time.Sleep(100 * time.Millisecond)
		}

		//activation is still pending, push back
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			//we will reintroduce this activation after 1 second
			time.Sleep(200 * time.Millisecond)
		} else if resp != nil && resp.StatusCode == http.StatusOK {
			//warining write ris null
			if writer != nil {

				var measurements falco.Measurement
				measurements = falco.Measurement(*get.Result)

				if measurements != nil {
					writeMeasurement(measurements, name, time.Duration(get.Duration), writer)
				} else {
					if name != "" {
						if payload, err := job.PayloadFromId(name); err == nil {
							writer.Add(payload.Runtime().MakeFailure(name, get.Cause, payload.SubmittedAt()))
						} else {
							if ow.Verbose {
								fmt.Printf("unknowen payload %s", name)
							}
						}
					}

					if ow.Verbose {
						fmt.Printf("%s failed due to %s:\n%+v", get.ActivationID, get.Cause, get.Logs)
					}
				}

			} else {
				//why are we dooing is with an empty writer?
			}
			//done with the mission...

			return
			//XXX: might be to much
			//if Verbose {
			//	fmt.Printf("got %+v\n", get)
			//}
		} else {
			if ow.Verbose {
				fmt.Printf("failed to get %s due to %+v\n", activationID, err)
			}
			//ow.writeError(activation,fmt.Sprintf("failed due to %+v",err),activation["rStart"],nil,writer)
		}
		//
		if tries > ow.maxRetry {
			fmt.Printf("could not fetch %s after %d tries\n", activationID, ow.maxRetry)
			if payload, err := job.PayloadFromId(name); err == nil {
				writer.Add(payload.Runtime().MakeFailure(name, "timeout", payload.SubmittedAt()))
			}
			return
		}
		//here comes the hack, we either wait using time.After for a fixed period or get canceled during it
		//side effect a request might still be finish should the ctx be canceled if it is currently performing a poll
		select {
		case <-job.Canceled():
			fmt.Printf("failed to collect %s\n", activationID)
			if payload, err := job.PayloadFromId(name); err == nil {
				writer.Add(payload.Runtime().MakeFailure(name, "activation canceled", payload.SubmittedAt()))
			}
			return
		case <-time.After(ow.BACKOFF):
			// if we reach this point than try again...
		}
	}
}

func (ow *OpenWhisk) connect() error {
	if ow.cli != nil {
		return nil
	}

	//TODO: check if we can pick a better client?

	baseurl, _ := whisk.GetURLBase(ow.Host, "/api")
	clientConfig := &whisk.Config{
		AuthToken: ow.Token,
		Namespace: "_",
		BaseURL:   baseurl,
		Version:   "v1",
		Insecure:  true,
		Host:      ow.Host,
		UserAgent: "Golang/Smile cli",
	}

	client, err := whisk.NewClient(http.DefaultClient, clientConfig)
	if err != nil {
		return err
	}

	ow.cli = client

	return nil
}

func (ow *OpenWhisk) Apply(opt OpenWhiskOption) {
	opt(ow)
}
