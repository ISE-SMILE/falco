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

package falco

import (
	"encoding/csv"
	"fmt"
	"os"
	"sync"
)

type ResultCollector interface {
	Add(measurement Measurement)
	Write(string2 string) error
	Print()
}

type CSVCollector struct {
	lock   sync.RWMutex
	data   map[string][]interface{}
	length int
}

func NewCollector() ResultCollector {
	return &CSVCollector{
		data:   make(map[string][]interface{}),
		length: 0,
	}
}

func (c *CSVCollector) Add(data Measurement) {
	c.lock.Lock()
	defer c.lock.Unlock()

	//invocations contains a per input file metrics everything else is job,global
	invocations := data["invocations"].([]interface{})
	data["jId"] = data.JobID()
	envInfo := make([]string, 0)
	for k := range data {
		if k != "invocations" {
			envInfo = append(envInfo, k)
		}
	}

	for _, elem := range invocations {
		invocation := elem.(map[string]interface{})
		//inject experiment JID
		for _, k := range envInfo {
			invocation[k] = data[k]
		}
		for k, v := range invocation {
			var list []interface{}
			if val, ok := c.data[k]; ok {
				list = val
			} else {
				list = make([]interface{}, 0)
			}
			list = append(list, v)
			c.data[k] = list
		}
		c.length++
	}
}

func (c *CSVCollector) Write(outputfile string) error {
	c.lock.RLock()
	defer c.lock.RUnlock()

	f, err := os.OpenFile(outputfile, os.O_CREATE|os.O_WRONLY, 0666)

	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)

	header := make([]string, 0)
	for k := range c.data {
		header = append(header, k)
	}

	err = w.Write(header)
	if err != nil {
		return err
	}

	fmt.Printf("%+v\n", c.data)

	records := make([][]string, 0)
	for i := 0; i < c.length; i++ {
		record := make([]string, 0)
		for _, key := range header {
			if i < len(c.data[key]) {
				record = append(record, fmt.Sprintf("%v", c.data[key][i]))
			} else {
				record = append(record, fmt.Sprintf("%v", nil))
			}
		}
		records = append(records, record)
	}

	err = w.WriteAll(records)
	if err != nil {
		return err
	}

	w.Flush()

	return nil
}

func (c *CSVCollector) Print() {
	c.lock.RLock()
	defer c.lock.RUnlock()

	header := make([]string, 0)
	for k := range c.data {
		fmt.Printf("\t%25s", k)
		header = append(header, k)
	}
	fmt.Println()

	for i := 0; i < c.length; i++ {
		for _, key := range header {
			if i < len(c.data[key]) {
				fmt.Printf("\t%25v", c.data[key][i])
			} else {
				fmt.Printf("\t%25v", nil)
			}
		}
		fmt.Println()
	}
}
