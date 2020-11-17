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

package executors

import (
	"encoding/binary"
	"fmt"
	"github.com/ISE-SMILE/falco"
	"github.com/docker/docker/pkg/random"
	"github.com/golang/protobuf/proto"
	"net"
	"testing"
	"time"
)

func TestTCPDriverChannel_SendOnce(t *testing.T) {
	port := int(8000 + random.Rand.Int31n(10000))
	channel := &TCPDriverChannel{}

	ctx := falco.NewContext("tcp")
	ctx.NewIntOption("driverPort", port)
	_ = channel.Setup(ctx)
	err := channel.Start(ctx.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer channel.Close()

	metrics, err := channel.ConsumeMetrics()

	for i := 0; i < 100; i++ {
		go func(id, port int) {
			<-time.After(time.Duration(random.Rand.Int63n(500)) * time.Millisecond)
			t.Logf("sending %d", id)
			conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
			check(err, t)
			message := &DriverMessage{
				Iid:         fmt.Sprintf("test%d", id),
				Status:      0,
				MetricsJSON: "{\"complex\":\"string\"}",
			}
			data, err := proto.Marshal(message)
			check(err, t)
			//write length
			binary.Write(conn, binary.LittleEndian, uint32(len(data)))
			conn.Write(data)
			err = conn.Close()
			check(err, t)
			t.Logf("done %d", id)
		}(i, port)
	}
	count := 0
	for i := 0; i < 100; i++ {
		select {
		case m := <-metrics:
			fmt.Printf("got %+v", m)
			count++
		case <-time.After(3 * time.Minute):
			t.Fatal("timeout")
		}
	}
	if count == 100 {
		t.Log("success")
	}

}

func check(err error, t *testing.T) {
	if err != nil {
		t.Logf("something failed %+v", err)
	}
}
