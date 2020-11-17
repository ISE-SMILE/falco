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
	"github.com/golang/protobuf/proto"
	"log"
	"net"
	"sync"
)

type TCPMessage struct {
	m *DriverMessage
}

func (T *TCPMessage) PayloadID() string {
	return T.m.Iid
}

func (T *TCPMessage) Status() falco.InvocationStatus {
	return falco.InvocationStatus(T.m.Status)
}

func (T *TCPMessage) Telemetry() []byte {
	return []byte(T.m.MetricsJSON)
}

func FromDriverMessage(message *DriverMessage) *TCPMessage {
	return &TCPMessage{message}
}

type TCPDriverChannel struct {
	port int
	pool *tcpPool
}

func (t *TCPDriverChannel) Setup(ctx *falco.Context) error {
	t.pool = newPool(ctx.Int("threads", 4), ctx.Int("maxConnections", 10000))
	t.port = ctx.Int("driverPort", 8888)
	return nil
}

func (t *TCPDriverChannel) Start(jobname string) error {

	go func() {
		err := t.pool.Listen(t.port)
		if err != nil {
			panic(err)
		}
	}()
	return nil
}

func (t *TCPDriverChannel) Close() error {
	t.pool.Close()
	return nil
}

func (t *TCPDriverChannel) consume() (<-chan DEQueueMessage, error) {
	out := make(chan DEQueueMessage)
	go func() {
		for {
			select {
			case m := <-t.pool.messages:
				out <- FromDriverMessage(m)
			}
		}
	}()
	return out, nil
}

func (t *TCPDriverChannel) Observe() (<-chan DEQueueMessage, error) {
	return t.consume()
}

func (t *TCPDriverChannel) ConsumeMetrics() (<-chan DEQueueMessage, error) {
	return t.consume()
}

type tcpPool struct {
	sync.Mutex
	workers        int
	maxConnections int
	closed         bool

	pendingConnections chan net.Conn
	done               chan struct{}
	messages           chan *DriverMessage
}

func newPool(w int, t int) *tcpPool {
	return &tcpPool{
		workers:            w,
		maxConnections:     t,
		pendingConnections: make(chan net.Conn, t),
		done:               make(chan struct{}),
		messages:           make(chan *DriverMessage),
	}
}

func (p *tcpPool) Close() {
	p.Lock()
	defer p.Unlock()

	p.closed = true
	close(p.done)
	close(p.pendingConnections)

}

func (p *tcpPool) addTask(conn net.Conn) {
	p.Lock()
	if p.closed {
		p.Unlock()
		return
	}
	p.Unlock()

	p.pendingConnections <- conn
}

func (p *tcpPool) start() {
	for i := 0; i < p.workers; i++ {
		go p.startWorker()
	}
}

func (p *tcpPool) startWorker() {
	for {
		select {
		case <-p.done:
			return
		case conn := <-p.pendingConnections:
			if conn != nil {
				p.handleConn(conn)
				_ = conn.Close()
			}
		}
	}
}

func (p *tcpPool) Listen(port int) error {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return err
	}

	p.start()

	for {
		conn, e := ln.Accept()
		if e != nil {
			if ne, ok := e.(net.Error); ok && ne.Temporary() {
				log.Printf("accept temp err: %v", ne)
				continue
			}

			log.Printf("accept err: %v", e)
			p.Close()
			return nil
		}

		p.addTask(conn)
	}

}

func (p *tcpPool) handleConn(conn net.Conn) {

	var length uint32
	err := binary.Read(conn, binary.LittleEndian, &length)
	if err != nil {
		log.Printf("failed to parse message %+v", err)
	}

	in := make([]byte, length)
	read, err := conn.Read(in)
	if err != nil {
		log.Printf("failed to parse message %+v", err)
	}

	if int(length) != read {
		panic(fmt.Errorf("expected more bytes got %d expected %d", read, length))
	}

	if err == nil {
		message := &DriverMessage{}
		if err := proto.Unmarshal(in, message); err != nil {
			log.Printf("failed to parse message %+v", err)
		} else {
			p.messages <- message
		}
	} else {
		log.Printf("failed to parse message %+v", err)
	}

}
