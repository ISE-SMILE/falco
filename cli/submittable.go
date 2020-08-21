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
	"context"
	"fmt"
	"github.com/ISE-SMILE/falco"
	"github.com/urfave/cli/v2"
	"os"
	"os/signal"
)

type SubmittableCommand interface {
	InvokerCommand
}

type Submitter struct {
	Invoker
	cmd        SubmittableCommand
	submitter  falco.Submittable
	strategies map[string]falco.ExecutionStrategy
}

func (s *Submitter) invokeStrategy(job *falco.Job, strategy falco.ExecutionStrategy, collector falco.ResultCollector) error {
	err := strategy.Execute(job, s.submitter, collector)

	if err != nil {
		return err
	}

	return nil
}

func (s *Submitter) addFlags(c *cli.Context, ctx *falco.Context) {
	readCommonFlags(c, ctx)

	ctx.NewDurationOption("timeout", c.Duration("timeout"))
	ctx.NewIntOption("threads", c.Int("threads"))
	ctx.NewIntOption("grouping", c.Int("grouping"))

	s.cmd.optionsFromFlags(c, ctx)
}

func (s *Submitter) AddSubmitCommand() *cli.Command {

	cmds := make([]*cli.Command, 0)
	for name, strategy := range s.strategies {
		cmds = append(cmds, &cli.Command{
			Name:    name,
			Aliases: nil,
			Usage:   "[jobname] [bucket] [jobfile]",
			Action: func(c *cli.Context) error {
				jobname := c.Args().Get(0)
				bucket := c.Args().Get(1)
				jobfile := c.Args().Get(2)

				ctx := falco.NewContext(jobname)

				keys, err := readJobsFile(jobfile)
				if err != nil {
					return err
				}

				fmt.Printf("read job-file found %d keys \n", len(keys))

				readCommonFlags(c, ctx)
				s.cmd.optionsFromFlags(c, ctx)

				fmt.Printf("payloads preped \n")

				collector := falco.NewCollector()

				//register an interrupt handler so we don't loose data ;)
				signalChan := make(chan os.Signal, 1)
				signal.Notify(signalChan, os.Interrupt)
				signalContext, cancelSignalContext := context.WithCancel(context.Background())
				defer cancelSignalContext()
				go func() {
					select {
					case sig := <-signalChan:
						fmt.Printf("Got %s signal. Aborting...\n", sig)
						err = writer(c.String("result"), jobname, collector)
						if err != nil {
							fmt.Printf("failed to write %+v\n", err)
						}
						os.Exit(1)
					case <-signalContext.Done():
						return
					}
				}()

				ctx.NewStingOption("inputBucket", bucket)

				payload, err := s.runtime.InvocationPayload(ctx, keys...)

				job := falco.NewJob(context.Background(), payload, c.Int("rps"), NewConsoleMonitor())

				if err != nil {
					return err
				}

				err = s.invokeStrategy(job, strategy, collector)
				if err != nil {
					return err
				}

				err = writer(c.String("result"), jobname, collector)

				return err
			},
		})
	}

	return &cli.Command{
		Name:    "job",
		Aliases: []string{"j"},
		Flags: []cli.Flag{
			&cli.IntFlag{
				Name:     "threads",
				Usage:    "number of threads for parallel execution",
				Required: false,
				Value:    4,
			},
			&cli.IntFlag{
				Name:     "rps",
				Usage:    "number of invocations per second",
				Required: false,
				Value:    60,
			},
			&cli.DurationFlag{
				Name:     "timeout",
				Usage:    "timeout for async jobs, default 5 minutes",
				Required: false,
			},
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
		Usage:       "sends an invocation to a AmaDA container",
		Subcommands: cmds,
	}
}

func writer(jobname, resultFileName string, collector falco.ResultCollector) error {
	if resultFileName != "" {
		err := collector.Write(fmt.Sprintf("%s%s", jobname, resultFileName))
		if err != nil {
			return err
		}
	} else {
		collector.Print()
	}
	return nil
}
