package docker

import (
	"fmt"
	"net/http"
	"strconv"

	cconfig "github.com/lamassuiot/lamassuiot/v3/core/pkg/config"
	dockerunner "github.com/lamassuiot/lamassuiot/v3/core/pkg/test/dockerrunner"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
)

func RunAWSEmulationLocalStackDocker() (func() error, *cconfig.AWSSDKConfig, error) {
	containerCleanup, container, dockerHost, err := dockerunner.RunDocker(dockertest.RunOptions{
		Repository: "localstack/localstack", // image
		Tag:        "latest",                // version
	}, func(hc *docker.HostConfig) {})
	if err != nil {
		return nil, nil, err
	}

	p, _ := strconv.Atoi(container.GetPort("4566/tcp"))
	endpoint := fmt.Sprintf("http://127.0.0.1:%d", p)
	// retry until server is ready
	err = dockerHost.Retry(func() error {
		r, err := http.DefaultClient.Get(endpoint)
		if err != nil {
			return err
		}

		if r.StatusCode != 200 {
			return fmt.Errorf("unexpected status code %s", r.Status)
		}

		return nil
	})

	if err != nil {
		containerCleanup()
		return nil, nil, err
	}

	return containerCleanup, &cconfig.AWSSDKConfig{
		EndpointURL:             endpoint,
		AccessKeyID:             "test",
		SecretAccessKey:         "test",
		AWSAuthenticationMethod: cconfig.Static,
		Region:                  "us-east-1",
	}, nil
}
