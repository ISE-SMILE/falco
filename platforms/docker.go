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

package platforms

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/ISE-SMILE/falco"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

//OpenWhiskDockerRunner implement a AsyncPlatfrom using the OpenWhisk docker runtime. This will create a single docker container for your runtime and use the OpenWhisk runtime api to perfrom deployment and invocations.
type OpenWhiskDockerRunner struct {
	cli *client.Client
	ctx context.Context
}

func (o OpenWhiskDockerRunner) FetchActivationLog(deployment falco.Deployment, invocation falco.Invocation) map[string]interface{} {
	if invocation.Result() != nil {
		return invocation.Result().(map[string]interface{})
	}
	return nil
}

func (o OpenWhiskDockerRunner) Submit(job *falco.AsyncInvocationPhase, deployment falco.Deployment,
	payload falco.Invocation, invocations chan<- falco.Invocation, options ...falco.InvocableOptions) error {

	job.TakeInvocation()

	inv, err := o.Invoke(deployment, payload)
	if err != nil {
		return err
	}

	if invocations != nil {
		invocations <- inv
	}

	payload.Submitted()
	job.SubmittedTask(payload)
	return nil
}

func (o OpenWhiskDockerRunner) Collect(job *falco.AsyncInvocationPhase,
	activations <-chan falco.Invocation, options ...falco.InvocableOptions) error {
	for {
		select {
		case activation, ok := <-activations:
			if ok {
				fmt.Printf("%+v\n", activation)
			}
		case <-job.IsCanceled():
			fmt.Printf("collection canceld with %d activations left\n", len(activations))
		}
	}

	return nil
}

type DockerDeployment struct {
	ContainerID   string
	containerName string
	nameSpace     string
	activationID  string
}

func (d DockerDeployment) DeploymentID() string {
	return fmt.Sprintf("%s_%s", d.containerName, d.ContainerID)
}

func ContainerName() string {
	return RandomStringWithCharset(8, charset)
}

func NewOpenWhiskDockerRunner(ctx context.Context) *OpenWhiskDockerRunner {
	docker, err := client.NewEnvClient()
	if err != nil {
		panic(fmt.Errorf("failed to init docker client cause:%+v", err))
	}
	cmd := OpenWhiskDockerRunner{
		cli: docker,
		ctx: ctx,
	}
	return &cmd
}

func (o OpenWhiskDockerRunner) Deploy(deployable falco.Deployable) (falco.Deployment, error) {
	containerName := ContainerName()

	containerReq, err := o.cli.ContainerCreate(o.ctx,
		&container.Config{
			Image:        deployable.Runtime().Identifier(),
			ExposedPorts: nat.PortSet{"8080": struct{}{}},
		},
		&container.HostConfig{
			PortBindings: map[nat.Port][]nat.PortBinding{
				"8080": {{HostIP: "127.0.0.1", HostPort: "8080"}},
			},
		}, nil, nil, containerName)

	if err != nil {
		return nil, err
	}

	err = o.cli.ContainerStart(o.ctx, containerReq.ID, types.ContainerStartOptions{})
	if err != nil {
		return nil, err
	}
	time.Sleep(30 * time.Second)
	deployment := &DockerDeployment{
		ContainerID:   containerReq.ID,
		containerName: containerName,
		nameSpace:     ContainerName(),
		activationID:  RandomStringWithCharset(15, charset),
	}

	envMap := map[string]string{
		"__OW_API_KEY":       "",
		"__OW_NAMESPACE":     deployment.nameSpace,
		"__OW_ACTION_NAME":   containerName,
		"__OW_ACTIVATION_ID": deployment.activationID,
	}
	deploymentContext := deployable.Option()

	for k, v := range deploymentContext.PrefixMap("env") {
		envMap[k] = v
	}

	msg := OpenWhiskMessage{
		Value: InitMessage{
			Name:   deployment.DeploymentID(),
			Main:   "none",
			Code:   deployable.Payload().(string),
			Binary: false,
			Env:    envMap,
		},
	}

	requestBody, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}

	initResp, err := http.Post("http://127.0.0.1:8080/init", "application/json",
		bytes.NewReader(requestBody))

	if err != nil {
		return nil, err
	}
	//TODO: remove
	fmt.Printf("%s send init, got:%d", containerReq.ID, initResp.StatusCode)

	return deployment, nil
}

func (o OpenWhiskDockerRunner) FetchDeployment(deplotmentID string) (falco.Deployment, error) {
	split := strings.Split(deplotmentID, "_")

	deployment := &DockerDeployment{
		ContainerID:   split[1],
		containerName: split[0],
		nameSpace:     ContainerName(),
		activationID:  RandomStringWithCharset(15, charset),
	}
	return deployment, nil
}

func (o OpenWhiskDockerRunner) Remove(deployment falco.Deployment) error {
	dockerDeployment := deployment.(*DockerDeployment)
	var cid = dockerDeployment.ContainerID

	c, err := o.cli.ContainerInspect(o.ctx, cid)
	if err != nil {
		return err
	}

	fmt.Printf("removing %10s %s %10s", c.ID, c.Name, c.Image)

	err = o.cli.ContainerRemove(o.ctx, cid, types.ContainerRemoveOptions{
		RemoveVolumes: false,
		RemoveLinks:   false,
		Force:         true,
	})

	return err
}

//Not available in docker (in this case)
func (o OpenWhiskDockerRunner) Scale(deployment falco.Deployment, options ...falco.ScaleOptions) (falco.Deployment, error) {
	return deployment, nil
}

func (o OpenWhiskDockerRunner) Invoke(deployment falco.Deployment, payload falco.Invocation) (falco.Invocation, error) {
	dockerDeployment := deployment.(*DockerDeployment)
	msg := RunMessage{
		Input:         payload,
		Namespace:     dockerDeployment.nameSpace,
		Name:          dockerDeployment.DeploymentID(),
		Key:           "DUMMY-KEY",
		ActivationID:  dockerDeployment.activationID,
		TransactionID: dockerDeployment.activationID,
	}

	requestBody, err := json.Marshal(msg)
	if err != nil {
		payload.SetError(err)
		return payload, err
	}

	start := time.Now()
	resp, err := http.Post("http://127.0.0.1:8080/run", "application/json", bytes.NewReader(requestBody))
	elapsed := time.Since(start)
	payload.Done(&elapsed)

	if err != nil {
		payload.SetError(err)
		return payload, err
	}

	if resp.StatusCode == 200 {
		data, err := ioutil.ReadAll(resp.Body)

		if err != nil {
			payload.SetError(err)
			return payload, err
		}

		measurements := make(map[string]interface{})
		err = json.Unmarshal(data, &measurements)

		if err != nil {
			payload.SetError(err)
			return payload, err
		}
		payload.SetRuntimeReference(dockerDeployment.ContainerID)
		payload.SetResult(measurements)
		return payload, nil
	} else {
		err = fmt.Errorf("invocation error [%d] %s - check the platfrom logs", resp.StatusCode, resp.Status)
		payload.SetError(err)
		return payload, err
	}

}
