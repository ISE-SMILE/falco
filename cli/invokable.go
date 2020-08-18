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
	"github.com/urfave/cli/v2"
)

type InvokerCommand interface {
	optionsFromFlags(c *cli.Context, ctx *falco.Context)
	deploymentFromFlags(c *cli.Context) falco.Deployment
}

type Invoker struct {
	runtime  falco.Runtime
	platform falco.Invokable
	cmd      InvokerCommand
}

func (i *Invoker) AddInvokeCommand() *cli.Command {
	return &cli.Command{
		Name:    "invoke",
		Aliases: []string{"i"},
		Usage:   "sends an invocation to a AmaDA container",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "result",
				Usage:    "result File location",
				Required: false,
				Value:    "result.csv",
			},
			&cli.IntFlag{
				Name:     "grouping",
				Usage:    "number of grouped files per payload",
				Required: false,
				Value:    1,
			},
		},
		Subcommands: []*cli.Command{
			{
				Name:      "file",
				Aliases:   []string{"f"},
				Usage:     "sends a single file-based invocation",
				ArgsUsage: "[jobname] [input file]",
				Action: func(c *cli.Context) error {
					jobname := c.Args().Get(0)
					input := c.Args().Get(1)

					ctx := falco.NewContext(jobname)
					readCommonFlags(c, ctx)
					i.cmd.optionsFromFlags(c, ctx)

					return i.file(ctx, i.cmd.deploymentFromFlags(c), input)
				},
			},
			{
				Name:      "s3",
				Aliases:   []string{"s"},
				Usage:     "sends a S3-URLs as invocation",
				ArgsUsage: "[jobname] [Input Bucket key] [jobfile]",
				Action: func(c *cli.Context) error {
					jobname := c.Args().Get(0)
					bucket := c.Args().Get(1)
					jobfile := c.Args().Get(2)
					keys, err := readJobsFile(jobfile)

					if err != nil {
						return err
					}

					ctx := falco.NewContext(jobname)
					readCommonFlags(c, ctx)
					ctx.NewStingOption("inputBucket", bucket)
					i.cmd.optionsFromFlags(c, ctx)

					return i.s3(ctx, i.cmd.deploymentFromFlags(c), keys)
				},
			},
			{
				Name:      "s3d",
				Aliases:   []string{"d"},
				Usage:     "sends a S3 URLs as invocation",
				ArgsUsage: "[jobname] [bucketName] [jobfile])",
				Action: func(c *cli.Context) error {
					jobname := c.Args().Get(0)
					bucket := c.Args().Get(1)
					jobfile := c.Args().Get(2)
					keys, err := readJobsFile(jobfile)

					if err != nil {
						return err
					}

					ctx := falco.NewContext(jobname)
					readCommonFlags(c, ctx)
					ctx.NewStingOption("inputBucket", bucket)
					i.cmd.optionsFromFlags(c, ctx)

					return i.s3(ctx, i.cmd.deploymentFromFlags(c), keys)
				},
			},
		},
	}
}

func (i *Invoker) invoke(mode int, ctx *falco.Context, deployment falco.Deployment, keys ...string) error {

	ctx.NewIntOption("mode", mode)
	payloads, err := i.runtime.InvocationPayload(ctx, keys...)
	if err != nil {
		return err
	}

	collector := falco.NewCollector()

	errors := make([]error, 0)
	for _, payload := range payloads {
		err = i.platform.Invoke(deployment, payload, collector)
		if err != nil {
			fmt.Printf("%s failed with %+v\n", payload.ID(), err)
			errors = append(errors, err)
		}
	}

	collector.Print()

	if len(errors) > 0 {
		return fmt.Errorf("invocation failed with:%+v", errors)
	}

	return nil
}

func (i *Invoker) s3(ctx *falco.Context, deployment falco.Deployment, keys []string) error {
	return i.invoke(1, ctx, deployment, keys...)
}

func (i *Invoker) s3d(ctx *falco.Context, deployment falco.Deployment, keys []string) error {
	return i.invoke(2, ctx, deployment, keys...)
}

func (i *Invoker) file(ctx *falco.Context, deployment falco.Deployment, input string) error {
	return i.invoke(0, ctx, deployment, input)
}
