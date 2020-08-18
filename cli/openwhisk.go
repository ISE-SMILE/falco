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

package cli

import (
	"fmt"
	"github.com/ISE-SMILE/falco"
	"github.com/ISE-SMILE/falco/executors"
	"github.com/ISE-SMILE/falco/platforms"
	"github.com/urfave/cli/v2"
	golang "runtime"
	"time"
)

func OWCommandSetup(commands []*cli.Command, platfrom *platforms.OpenWhisk, runtime falco.Runtime) []*cli.Command {

	cmd := OWCommand{
		runner: platfrom,
	}

	inv := Invoker{
		runtime:  runtime,
		platform: cmd.runner,
		cmd:      &cmd,
	}

	var samplesize float32 = 0.2

	sub := Submitter{
		Invoker:   inv,
		cmd:       &cmd,
		submitter: cmd.runner,
		strategies: map[string]falco.ExecutionStrategy{
			"async": &executors.AsyncExecutor{Timeout: 10 * time.Minute},
			"seq":   &executors.SequentialExecutor{},
			"parallel": &executors.ParallelExecutor{
				Threads: golang.NumCPU(),
			},
			//TODO: fix queueConnection..
			"dist": &executors.DistributedExecutor{
				Queue:        executors.RabbitMQWrapper{},
				Timeout:      0,
				TestInterval: 200,
				Strategy: executors.MeanBackoffStragglerStrategy{
					ReTryThreshold:    3,
					MinimumSampleSize: &samplesize,
					Graceperiod:       time.Millisecond * 100,
				},
			},
		},
	}

	commands = append(commands, &cli.Command{
		Name:    "ow",
		Aliases: []string{"ow"},
		Before: func(c *cli.Context) error {
			//inject settings based on flags
			targetHost := c.String("host")
			if targetHost != "" {
				platfrom.Apply(platforms.WithHost(targetHost))
			}
			authToken := c.String("auth")
			if authToken != "" {
				platfrom.Apply(platforms.WithAuthToken(authToken))
			}

			return nil
		},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "host",
				Usage:    "OpenWhisk Address",
				Required: false,
				Value:    "localhost",
			},
			&cli.StringFlag{
				Name:  "auth",
				Usage: "OpenWhisk Authorization Token",
				//TODO: remove
				Required: false,
				Value:    "noop",
			},
			&cli.StringFlag{
				Name:     "action",
				Usage:    "OW action name",
				Required: false,
				Value:    "test",
			},
		},
		Usage: "util to interact with OpenWhisk deployments of the AmeDA platform",
		Subcommands: []*cli.Command{
			{
				Name:    "deploy",
				Aliases: []string{"d"},
				Usage:   "deploys a new runtime to OpenWhisk",
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:     "compiled",
						Aliases:  []string{"cmp"},
						Usage:    "Indicate that the provided template is compiled or not",
						Value:    false,
						Required: false,
					},
				},
				ArgsUsage: "[jobname] [template file] [script file] ",
				Action: func(c *cli.Context) error {
					jobname := c.Args().Get(0)
					files := c.Args().Slice()[1:]

					ctx := falco.NewContext(jobname)

					readCommonFlags(c, ctx)

					ctx.NewStingOption("action", c.String("action"))

					deployable, err := runtime.MakeDeployment(ctx, files...)
					if err != nil {
						return err
					}

					deployment, err := cmd.runner.Deploy(deployable)

					if err != nil {
						return err
					}
					fmt.Printf("deployed %s\n", deployment.ID())
					return nil
				},
			},
			{
				Name:    "remove",
				Aliases: []string{"rm"},
				Usage:   "removes a runtime from OpenWhisk",

				Action: func(c *cli.Context) error {
					dep := cmd.deploymentFromFlags(c)

					return cmd.runner.Remove(dep)
				},
			},
			{
				Name:  "update",
				Usage: "updates an existing deployment",
				Flags: []cli.Flag{
					&cli.IntFlag{
						Name:     "memory",
						Aliases:  []string{"m"},
						Usage:    "Amount of Memory for the function",
						Value:    256,
						Required: true,
					},
				},
				ArgsUsage: "[jobname] [template file] [script file] ",
				Action: func(c *cli.Context) error {
					dep := cmd.deploymentFromFlags(c)
					memory := c.Int("memory")
					dep, err := cmd.runner.Scale(dep, platforms.ScaleMemory(memory))
					if err == nil {
						fmt.Printf("updated %s with %d memory", dep.ID(), memory)
					}
					return err
				},
			},
			inv.AddInvokeCommand(),
			sub.AddSubmitCommand(),
		},
	})

	return commands
}

type OWCommand struct {
	runner *platforms.OpenWhisk
}

func (*OWCommand) deploymentFromFlags(c *cli.Context) falco.Deployment {
	dep := platforms.OpenWhiskDeployment{
		ActionName: c.String("action"),
	}
	return dep
}

func (ow *OWCommand) optionsFromFlags(c *cli.Context, ctx *falco.Context) {
	//TODO??
}
