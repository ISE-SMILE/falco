/*
 * MIT License
 *
 * Copyright (c) 2020 Sebastian Werner
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

package cli

import (
	"github.com/ISE-SMILE/falco"
	"github.com/ISE-SMILE/falco/platforms"
	"github.com/urfave/cli/v2"
	"testing"
)

func TestRun(t *testing.T) {
	runtime := &falco.MockRuntime{}

	whiksRunner, err := platforms.NewOpenWhisk()

	if err != nil {
		panic(err)
	}

	cmds := make([]*cli.Command, 0)

	cmds = OWCommandSetup(cmds, whiksRunner, runtime)

	app := &cli.App{
		EnableBashCompletion: true,
		Name:                 "falco",
		Flags:                SetupCommonFlags(),
		Commands:             cmds,
		Before: func(c *cli.Context) error {
			SetFlags(c)
			return nil
		},
	}

	testArgs := []string{
		"test", "ow", "--host", "testing", "--auth", "testauth",
	}

	err = app.Run(testArgs)

	if err != nil {
		t.Fail()
	}

	if whiksRunner.Host != "testing" {
		t.Fail()
	}

	if whiksRunner.Token != "testauth" {
		t.Fail()
	}

	testArgs = []string{
		"test", "ow", "--host", "testing2",
	}

	err = app.Run(testArgs)
	if whiksRunner.Host == "testing" {
		t.Fail()
	}

	//default is no auth is provided
	if whiksRunner.Token != "noop" {
		t.Fail()
	}
}
