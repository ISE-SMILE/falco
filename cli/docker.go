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
	"github.com/ISE-SMILE/falco/platforms"
	"github.com/urfave/cli/v2"
)

type DockerCommand struct {
	runner *platforms.OpenWhiskDockerRunner
}

func (d *DockerCommand) optionsFromFlags(c *cli.Context, ctx *falco.Options) {
	ctx.NewStingOption("host", c.String("host"))
	ctx.NewIntOption("port", c.Int("port"))
}

func (d *DockerCommand) deploymentFromFlags(c *cli.Context) falco.Deployment {
	return platforms.DockerDeployment{
		ContainerID: c.String("cli"),
	}
}

func DockerCommandSetup(commands []*cli.Command,
	runner *platforms.OpenWhiskDockerRunner,
	runtime falco.Runtime) []*cli.Command {

	cmd := DockerCommand{
		runner: runner,
	}

	inv := Invoker{
		runtime:  runtime,
		platform: cmd.runner,
		cmd:      &cmd,
	}

	commands = append(commands, &cli.Command{
		Name:    "docker",
		Aliases: []string{"d"},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "host",
				Usage:    "address of the platform",
				Required: false,
				Value:    "localhost",
			},
			&cli.IntFlag{
				Name:     "port",
				Usage:    "port of the platform",
				Required: false,
				Value:    8080,
			},
			&cli.StringFlag{
				Name:     "cid",
				Usage:    "Container ID",
				Required: false,
				Value:    "",
			},
		},
		Usage: "util to interact with docker deployments of the AmeDA platform",
		Subcommands: []*cli.Command{
			{
				Name:    "deploy",
				Aliases: []string{"d"},
				Usage:   "deploys and initilizes a new runtime using docker",
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:     "compiled",
						Aliases:  []string{"cmp"},
						Usage:    "Indicate that the provided template is compiled or not",
						Value:    false,
						Required: false,
					},
				},
				ArgsUsage: "[jobname] [file1] ... [fileN]",
				Action: func(c *cli.Context) error {
					jobname := c.Args().Get(0)

					files := c.Args().Slice()[1:]

					ctx := falco.NewFacloOptions(jobname)

					readCommonFlags(c, ctx)
					cmd.optionsFromFlags(c, ctx)

					deployable, err := runtime.MakeDeployment(ctx, files...)
					if err != nil {
						return err
					}

					deployment, err := cmd.runner.Deploy(deployable)

					if err == nil {
						fmt.Printf("Deplyment successfull %s", deployment.ID())
					}

					return err
				},
			},
			{
				Name:    "remove",
				Aliases: []string{"rm"},
				Usage:   "removes a AmeDA platform using docker",
				Action: func(c *cli.Context) error {
					deployment := cmd.deploymentFromFlags(c)

					return cmd.runner.Remove(deployment)
				},
			},
			inv.AddInvokeCommand(),
		},
	})

	return commands
}
