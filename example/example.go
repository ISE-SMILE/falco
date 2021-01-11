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

package main

import (
	"flag"
	"fmt"
	"github.com/ISE-SMILE/falco"
	"github.com/ISE-SMILE/falco/executors"
	"github.com/ISE-SMILE/falco/platforms"
)

const payload = `def main(args):
    name = args.get("name", "stranger")
    greeting = "Hello " + name + "!"
    print(greeting)
    return {"greeting": greeting}`

type ExampleDriver struct {
	plan *falco.ExecutionPlan
}

type ExampleRuntime struct{}

func (e ExampleRuntime) Identifier() string {
	return "python:3"
}

func (e *ExampleRuntime) MakeDeployment(options *falco.Options, s ...string) (falco.Deployable, error) {
	return falco.NewStringDeployable(payload, e), nil
}

func (e *ExampleRuntime) InvocationPayload(options *falco.Options, s ...string) ([]falco.Invocation, error) {
	return []falco.Invocation{falco.NewSimpleInvocation("world", e)}, nil
}

func (ed *ExampleDriver) Runtime() falco.Runtime {
	return &ExampleRuntime{}
}

func (ed *ExampleDriver) ExecutionPlan() *falco.ExecutionPlan {
	return ed.plan
}

func (ed *ExampleDriver) Execute(strategy falco.ExecutionStrategy, platform falco.AsyncPlatform) error {
	var stage = ed.plan
	for stage != nil {
		phase := stage.Phase

		err := strategy.Execute(phase, phase.Deployment, platform)
		if err != nil {
			return fmt.Errorf("failed on stage %s cause:%+v", phase.ID, err)
		}

		stage = stage.Next()
	}

	stage = ed.plan
	for stage != nil {
		phase := stage.Phase

		for _, invocation := range phase.Payloads {
			fmt.Printf("%s: %+v%+v\n", invocation.InvocationID(), invocation.Result(), invocation.Error())
		}
		stage = stage.Next()
	}

	return nil
}

func (ed *ExampleDriver) Deploy(platform falco.AsyncPlatform) {
	var stage = ed.plan
	for stage != nil {
		phase := stage.Phase
		deployable, _ := ed.Runtime().MakeDeployment(nil)
		deployment, err := platform.Deploy(deployable)
		if err != nil {
			fmt.Printf("failed to deoloy stage %s cause:%+v\n", phase.ID, err)
		}
		phase.Deployment = deployment

		stage = stage.Next()
	}

}

func (ed *ExampleDriver) Remove(platform falco.AsyncPlatform) {
	var stage = ed.plan
	for stage != nil {
		phase := stage.Phase
		err := platform.Remove(phase.Deployment)
		if err != nil {
			fmt.Printf("failed to undeploy stage %s cause:%+v\n", phase.ID, err)
		}
		stage = stage.Next()
	}
}

func main() {
	host := flag.String("host", "", "OpenWhisk Host")
	token := flag.String("token", "", "OpenWhisk Token")
	flag.Parse()

	whisk, err := platforms.NewOpenWhisk(platforms.WithHost(*host), platforms.WithAuthToken(*token))
	if err != nil {
		panic(err)
	}
	runtime := ExampleRuntime{}

	plan := &falco.ExecutionPlan{
		Deployable: nil,
		Phase: &falco.AsyncInvocationPhase{
			ID:         "test",
			Payloads:   func() []falco.Invocation { payload, _ := runtime.InvocationPayload(nil); return payload }(),
			Deployment: nil,
		},
	}
	driver := ExampleDriver{
		plan: plan,
	}

	driver.Deploy(whisk)
	fmt.Println(driver.Execute(executors.SequentialExecutor{}, whisk))
	driver.Remove(whisk)
}
