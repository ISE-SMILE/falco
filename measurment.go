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

package falco

import (
	"time"
)

type Measurement map[string]interface{}

func (m Measurement) WithDefaults() Measurement {

	m.set("jId","")
	m.set("fId","")
	m.set("rLat","")

	return m
}

func(m Measurement) set(key string,val interface{}){
	if _,ok := m[key]; !ok {
		m[key] = val
	}
}

func (data Measurement) get(name string,defaultVal interface{}) interface{} {
	if val,ok :=  data[name];ok {
		if val != nil {
			return val
		}
	}
	return defaultVal
}

func (data Measurement) InvocationID() string{
	return data.get("IId","").(string)
}

func (data Measurement) JobID() string{
return data.get("jId","").(string)
}

func (data Measurement) IsFailure() bool{
	return data.get("failed",false).(bool)
}

func (data Measurement) SetRequestLatency(latency time.Duration)  {
	data["rLat"] = latency.Milliseconds()
}

func (data Measurement) SetInvocationID(name string)  {
	data["IId"] = name
}

func (data Measurement) SetJobID(name string)  {
	data["jId"] = name
}