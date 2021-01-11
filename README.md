# Falco - <ins>Fa</ins>aS-based <ins>l</ins>arge-scale <ins>Co</ins>mputing 
<p align="center">
 <img src="https://raw.githubusercontent.com/ISE-SMILE/falco/master/logo.svg" height=170/>
</p>

<!--TODO: Logo / possible rename? -->

## About
Library to implement custom FaaS-based massive parallel analytics piplines. 
Falco provides interfaces to implement a custom Driver for you'r analytics piplline,
allowing you to manage execution and coordination of your functions without worrining about
deployment needs. 

### Build With
 * [go 1.14](https://golang.org/dl/)
### Usage
Falco is a library, thus to use it you need to first implement some falco interfaces to use it properply.
Check out the Getting Staarted section of the readme for a hands on example. In general Falco uses a Driver abstraction to manage FaaS Analytics Pipelines.
A driver can Deploy, Execute and Remove workloads from `falco.Platform`. Falco comes with multiple pre-Build platforms, see `platforms/`.

Each `falco.Driver` need a Runtime, the runtime is the application that runs on the FaaS Platform, since a driver and a runtime are closely coupled it makes sense to developme them together.

Once you implemented the Driver and Runtime for your use-case you can use falco to get execution on multiple platforms for free.

## Getting Started

Sample Driver/Runtime based on python:3 on OpenWhisk 
```go
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
	return falco.NewStringDeployable(payload,e),nil
}

func (e *ExampleRuntime) InvocationPayload(options *falco.Options, s ...string) ([]falco.Invocation, error) {
	return []falco.Invocation{falco.NewSimpleInvocation("world",e)},nil
}

func (ed *ExampleDriver) Runtime() falco.Runtime {
	return &ExampleRuntime{}
}

func (ed *ExampleDriver)  ExecutionPlan() *falco.ExecutionPlan {
	return ed.plan
}

func (ed *ExampleDriver)  Execute(strategy falco.ExecutionStrategy, platform falco.AsyncPlatform) error {
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
			fmt.Printf("%s: %+v%+v\n",invocation.InvocationID(),invocation.Result(),invocation.Error())
		}
		stage = stage.Next()
	}

	return nil
}

func (ed *ExampleDriver)  Deploy(platform falco.AsyncPlatform) {
	var stage = ed.plan
	for stage != nil {
		phase := stage.Phase
		deployable,_ := ed.Runtime().MakeDeployment(nil)
		deployment,err := platform.Deploy(deployable)
		if err != nil {
			fmt.Printf("failed to deoloy stage %s cause:%+v\n", phase.ID, err)
		}
		phase.Deployment = deployment

		stage = stage.Next()
	}


}

func (ed *ExampleDriver)  Remove(platform falco.AsyncPlatform) {
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

func main(){
	host := flag.String("host","","OpenWhisk Host")
	token := flag.String("token","","OpenWhisk Token")
	flag.Parse()

	whisk, err := platforms.NewOpenWhisk(platforms.WithHost(*host), platforms.WithAuthToken(*token))
	if err != nil{
		panic(err)
	}
	runtime := ExampleRuntime{}

	plan := &falco.ExecutionPlan{
		Deployable: nil,
		Phase:      &falco.AsyncInvocationPhase{
			ID:         "test",
			Payloads:   func() []falco.Invocation {payload,_ := runtime.InvocationPayload(nil);return payload}(),
			Deployment: nil,
		},
	}
	driver := ExampleDriver{
		plan: plan,
	}

	driver.Deploy(whisk)
	fmt.Println(driver.Execute(executors.SequentialExecutor{},whisk))
	driver.Remove(whisk)
}
```

Run with `go run example/example.go -host=<OpenWhik Host Address> -token=<OpenWhisk Token>`

## Roadmap
 * Integration of Fact and Meeter Projects 
 * Implementation of AWS Platform
 * Implementation of Google Platform

## License
Distributed under the MIT License. See LICENSE for more information.

## Acknowledgements
Created in the context of SMILE. SMILE is a Software Campus Project funded by BMBF. More Information at: [https://ise-smile.github.io/](https://ise-smile.github.io/).
 
