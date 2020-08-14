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
	"github.com/ISE-SMILE/falco/platforms"
	"github.com/urfave/cli/v2"
	"log"
	"os"
	"time"
)

var CommitHash string

func Run(runtime falco.Runtime) {

	ctx := context.Background()

	dockerRunner := platforms.NewOpenWhiskDockerRunner(ctx)

	whiksRunner, err := platforms.NewOpenWhisk()

	if err != nil {
		panic(err)
	}

	start := time.Now()
	cmds := make([]*cli.Command, 0)

	cmds = DockerCommandSetup(cmds, dockerRunner, runtime)
	cmds = OWCommandSetup(cmds, whiksRunner, runtime)

	app := &cli.App{
		EnableBashCompletion: true,
		Name:                 "falco",
		Usage:                fmt.Sprintf("SMILE FaaS Runner Utility, v0"),
		Flags:                SetupCommonFlags(),
		Commands:             cmds,
		Before: func(c *cli.Context) error {
			SetFlags(c)
			//inject settings based on flags
			targetHost := c.String("host")
			if targetHost != "" {
				whiksRunner.Apply(platforms.WithHost(targetHost))
			}
			authToken := c.String("auth")
			if authToken != "" {
				whiksRunner.Apply(platforms.WithAuthToken(authToken))
			}

			return nil
		},
	}

	err = app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}

	elapsed := time.Now().Sub(start)
	fmt.Printf("\nrun job %+v\n", elapsed)
}
