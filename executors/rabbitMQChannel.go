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
	"encoding/json"
	"fmt"
	"github.com/ISE-SMILE/falco"
	"github.com/streadway/amqp"
	"net/url"
	"strconv"
	"strings"
)

type RabbitMQWrapper struct {
	QueueConnection *amqp.Connection
	Channel         *amqp.Channel
	Queues          map[string]amqp.Queue

	controlQueueName string
	metricsQueueName string
}

//RabbitMQWrapper

type RabbidmqMessage struct {
	id     string
	status int
	raw    []byte
}

//returns payloadID refernece for this message
func (r RabbidmqMessage) PayloadID() string {
	return r.id
}

//returns the status of a invocation
func (r RabbidmqMessage) Status() falco.InvocationStatus {
	return falco.InvocationStatus(r.status)
}

func (r RabbidmqMessage) Telemetry() []byte {
	return r.raw
}

func FromDelivery(d amqp.Delivery) *RabbidmqMessage {
	content := string(d.Body)
	flagstone := strings.Count(content, ",")
	if flagstone > 1 {
		var message map[string]interface{}

		err := json.Unmarshal(d.Body, &message)

		status := int(falco.Success)
		id := ""
		if err != nil {
			status = int(falco.Failure)
			id = "error"
		} else {
			if message["failed"] == "true" {
				status = int(falco.Failure)
			}
			id = message["IId"].(string)

		}

		return &RabbidmqMessage{
			id:     id,
			status: status,
			raw:    d.Body,
		}
	} else {
		message := strings.Split(content, ",")
		status, err := strconv.Atoi(message[1])
		if err != nil {
			status = int(falco.Failure)
		}
		return &RabbidmqMessage{
			id:     message[0],
			status: status,
			raw:    d.Body,
		}
	}
}

//Setup the following values must be set in the context:
// rmquser - username of rabidmq (default guest)
// rmqpass - password of rabidmq user (default guest)
// rmq - address (ip or hostname) for rabidmq (default localhost)
// rmqport - port for rabidmq (default 5672)
func (r *RabbitMQWrapper) Setup(c *falco.Context) error {
	rmqURL := fmt.Sprintf("amqp://%s:%s@%s:%d/",
		url.QueryEscape(c.String("rmquser", "guest")),
		url.QueryEscape(c.String("rmqpass", "guest")),
		c.String("rmq", "localhost"),
		c.Int("rmqport", 5672),
	)

	conn, err := amqp.Dial(rmqURL)
	if err != nil {
		return err
	}
	r.QueueConnection = conn

	return nil
}

func (r *RabbitMQWrapper) Start(jobname string) error {
	ch, err := r.QueueConnection.Channel()

	if err != nil {
		return err
	}

	r.Channel = ch

	r.controlQueueName = jobname
	r.metricsQueueName = fmt.Sprintf("%s-metrics", r.controlQueueName)

	err = r.Open(r.controlQueueName)
	if err != nil {
		return err
	}
	err = r.Open(r.metricsQueueName)
	if err != nil {
		return err
	}

	//remove content of privious runs?
	_ = r.Purge(r.controlQueueName)
	_ = r.Purge(r.metricsQueueName)

	return nil
}

func (r *RabbitMQWrapper) Close() error {
	_ = r.Delete(r.controlQueueName)
	_ = r.Delete(r.metricsQueueName)

	_ = r.Channel.Close()
	return r.QueueConnection.Close()
}

func (r *RabbitMQWrapper) Delete(name string) error {
	_, err := r.Channel.QueueDelete(name, true, true, true)
	return err
}

func (r *RabbitMQWrapper) Open(name string) error {
	if !r.QueueConnection.IsClosed() {
		if _, ok := r.Queues[name]; !ok {
			queue, err := r.Channel.QueueDeclare(name, false, false, false, false, nil)
			if err != nil {
				return err
			}

			r.Queues[name] = queue
		}

		return nil
	} else {
		return fmt.Errorf("queue connection is closed")
	}
}

func (r *RabbitMQWrapper) Purge(name string) error {
	if !r.QueueConnection.IsClosed() {
		_, err := r.Channel.QueuePurge(name, true)
		return err
	} else {
		return fmt.Errorf("queue connection is closed")
	}
}

func (r *RabbitMQWrapper) consume(name string) (<-chan DEQueueMessage, error) {
	out := make(chan DEQueueMessage)
	messages, err := r.Channel.Consume(
		name,  // queue
		"",    // consumer
		true,  // auto-ack
		false, // exclusive
		false, // no-local
		false, // no-wait
		nil,   // args
	)
	if err != nil {
		return nil, err
	}

	go func() {
		for {
			select {
			case d := <-messages:
				out <- FromDelivery(d)
			}
		}
	}()

	return out, nil
}

//this call is used to observe updates on the job, without any telemetry
func (r *RabbitMQWrapper) Observe() (<-chan DEQueueMessage, error) {
	return r.consume(r.controlQueueName)
}

//this call is used to observe updates on a job including telemetry data
func (r *RabbitMQWrapper) ConsumeMetrics() (<-chan DEQueueMessage, error) {
	return r.consume(r.metricsQueueName)
}
