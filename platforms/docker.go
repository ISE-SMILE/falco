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
	"time"
)

type OpenWhiskDockerRunner struct {
	cli *client.Client
	ctx context.Context
}

type DockerDeployment struct {
	ContainerID   string
	containerName string
	nameSpace     string
	activationID  string
}

func (d DockerDeployment) ID() string {
	return fmt.Sprintf("%s_%s", d.containerName, d.ContainerID)
}

func ContainerName() string {
	return StringWithCharset(8, charset)
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
			Image:        deployable.Runtime(),
			ExposedPorts: nat.PortSet{"8080": struct{}{}},
		},
		&container.HostConfig{
			PortBindings: map[nat.Port][]nat.PortBinding{
				"8080": {{HostIP: "127.0.0.1", HostPort: "8080"}},
			},
		}, nil, containerName)

	if err != nil {
		return nil, err
	}

	err = o.cli.ContainerStart(o.ctx, containerReq.ID, types.ContainerStartOptions{})
	if err != nil {
		return nil, err
	}

	deployment := &DockerDeployment{
		ContainerID:   containerReq.ID,
		containerName: containerName,
		nameSpace:     ContainerName(),
		activationID:  StringWithCharset(15, charset),
	}

	envMap := map[string]string{
		"__OW_API_KEY":       "",
		"__OW_NAMESPACE":     deployment.nameSpace,
		"__OW_ACTION_NAME":   containerName,
		"__OW_ACTIVATION_ID": deployment.activationID,
	}
	deploymentContext := deployable.Context()

	for k, v := range deploymentContext.PrefixMap("env") {
		envMap[k] = v
	}

	msg := OpenWhiskMessage{
		Value: InitMessage{
			Name:   deployment.ID(),
			Main:   "none",
			Code:   deployable.Payload(),
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

func (o OpenWhiskDockerRunner) Remove(deployment falco.Deployment) error {
	dockerDeployment := deployment.(DockerDeployment)
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

func (o OpenWhiskDockerRunner) Invoke(deployment falco.Deployment, payload falco.InvocationPayload, collector falco.ResultCollector) error {
	dockerDeployment := deployment.(DockerDeployment)
	msg := RunMessage{
		Input:         payload,
		Namespace:     dockerDeployment.nameSpace,
		Name:          dockerDeployment.ID(),
		Key:           "DUMMY-KEY",
		ActivationID:  dockerDeployment.activationID,
		TransactionID: dockerDeployment.activationID,
	}

	requestBody, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	start := time.Now()
	resp, err := http.Post("http://127.0.0.1:8080", "application/json", bytes.NewReader(requestBody))
	elapsed := time.Since(start)

	if err != nil {
		return err
	}

	data, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return err
	}

	if resp.StatusCode == 200 && collector != nil {
		measurements := make(falco.Measurement)
		err = json.Unmarshal(data, &measurements)

		if err != nil {
			return nil
		}

		payload.Runtime().MakeMeasurement(measurements)

		measurements.SetJobID(deployment.ID())

		writeMeasurement(measurements, payload.ID(), elapsed, collector)
	}

	return nil
}
