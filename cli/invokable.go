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

func (i *Invoker) addFlags(c *cli.Context, ctx *falco.Context) {
	readCommonFlags(c, ctx)
	ctx.NewIntOption("grouping", c.Int("grouping"))
	ctx.NewStingOption("result", c.String("result"))
	i.cmd.optionsFromFlags(c, ctx)
}

func (i *Invoker) AddInvokeCommand() *cli.Command {

	cmds := make([]*cli.Command, 0)
	for _, s := range i.runtime.InvocationStrategies() {
		cmd := &cli.Command{
			Name:      s.StrategyName(),
			Usage:     s.StrategyUsage(),
			ArgsUsage: "[jobname] [bucket] [jobfile]",
			Action: func(c *cli.Context) error {
				jobname := c.Args().Get(0)
				bucket := c.Args().Get(1)
				jobfile := c.Args().Get(2)
				keys, err := readJobsFile(jobfile)

				if err != nil {
					return err
				}

				ctx := falco.NewContext(jobname)
				i.addFlags(c, ctx)
				ctx.NewStingOption("inputBucket", bucket)

				payloads, err := s.InvocationPayload(ctx, bucket, keys...)
				if err != nil {
					return err
				}

				collector := falco.NewCollector()

				errors := make([]error, 0)
				deployment := i.cmd.deploymentFromFlags(c)
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
			},
		}
		cmds = append(cmds, cmd)
	}

	return &cli.Command{
		Name:    "invoke",
		Aliases: []string{"i"},
		Usage:   "sends an invocation to the deployed runtime",
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
		Subcommands: cmds,
	}
}
