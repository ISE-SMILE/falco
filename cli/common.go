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
	"bufio"
	"fmt"
	"github.com/ISE-SMILE/falco"
	"github.com/urfave/cli/v2"
	"io"
	"net/url"
	"os"
)


func SetupCommonFlags() []cli.Flag {
	flags := make([]cli.Flag, 0)

	flags = append(flags, s3Flags()...)
	flags = append(flags, rmqFlags()...)
	return flags

}

func rmqFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:     "rmq",
			Usage:    "RabbitMQ Address",
			Required: false,
			Value:    "localhost",
		},
		&cli.IntFlag{
			Name:     "rmqport",
			Usage:    "RabbitMQ Port",
			Required: false,
			Value:    5672,
		},
		&cli.StringFlag{
			Name:     "rmquser",
			Usage:    "RabbitMQ Username",
			Required: false,
			Value:    "smile",
		},
		&cli.StringFlag{
			Name:     "rmqpass",
			Usage:    "RabbitMQ Password",
			Required: false,
			Value:    "test",
		},
	}
}

func s3Flags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:     "s3",
			Usage:    "S3 Endpoint",
			Required: false,
			Value:    "localhost:9000",
		},
		&cli.StringFlag{
			Name:     "s3access",
			Aliases:  []string{"s3a"},
			Usage:    "S3 Access Key",
			Required: false,
			Value:    "test",
		},
		&cli.StringFlag{
			Name:     "s3secret",
			Usage:    "S3 Secret Key",
			Aliases:  []string{"s3s"},
			Required: false,
			Value:    "testtest",
		},
		&cli.StringFlag{
			Name:     "s3prot",
			Aliases:  []string{"s3p"},
			Usage:    "S3 Protocol",
			Required: false,
			Value:    "HTTP",
		},
		&cli.StringFlag{
			Name:     "s3sign",
			Aliases:  []string{"s3n"},
			Usage:    "S3 Signer Method",
			Required: false,
			Value:    "AWSS3V4SignerType",
		},
		&cli.BoolFlag{
			Name:     "verbose",
			Aliases:  []string{"v"},
			Usage:    "enable verbose logging",
			Required: false,
		},
	}
}

var verbose = false

//read global flags
func SetFlags(c *cli.Context) {
	verbose = c.Bool("verbose")
}

func readCommonFlags(c *cli.Context, ctx *falco.Context) {
	//read into params
	if ctx != nil {
		ctx.NewStingOption("S3",c.String("s3"))
		ctx.NewStingOption("LOCAL_ACCESS_KEY_ID",c.String("s3access"))
		ctx.NewStingOption("LOCAL_SECRET_KEY",c.String("s3secret"))
		ctx.NewStingOption("S3_PROTOCOL",c.String("s3prot"))
		ctx.NewStingOption("S3_SIGNER",c.String("s3sign"))
		ctx.NewStingOption("S3_PREFIX","LOCAL")

		ctx.NewStingOption("rmq_host",c.String("rmq"))
		ctx.NewStingOption("rmq_port",fmt.Sprintf("%d", c.Int("rmqport")))
		ctx.NewStingOption("rmq_user",c.String("rmquser"))
		ctx.NewStingOption("rmq_password",c.String("rmqpass"))
	}
}

func rmqConnectionStringFromFlags(c *cli.Context) string {
	return fmt.Sprintf("amqp://%s:%s@%s:%d/", url.QueryEscape(c.String("rmquser")), url.QueryEscape(c.String("rmqpass")), c.String("rmq"), c.Int("rmqport"))
}


func writeResults(resultFile string, writer *falco.ResultCollector) error {
	if writer != nil {
		if verbose {
			fmt.Printf("wrinting results to %s\n", resultFile)
		}
		err := writer.Write(resultFile)
		if err != nil {
			return err
		}
	}
	return nil
}


//func addFlags(c *cli.Context) map[string]string {
//	params := make(map[string]string)
//	readCommonFlags(c, params)
//	return params
//}


func readJobsFile(jobfile string) ([]string, error) {
	file,err := os.Open(jobfile)

	if err != nil{
		return nil,err
	}

	defer file.Close()
	keys := make([]string,0)
	reader := bufio.NewReader(file)
	var line string
	for {
		line, err = reader.ReadString('\n')

		if err != nil {
			break
		}
		keys = append(keys,line)
	}

	if err != io.EOF {
		return nil,err
	} else {
		return keys,nil
	}

}