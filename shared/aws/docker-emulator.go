package aws

import (
	"fmt"
	"net/http"
	"strconv"

	dockerrunner "github.com/lamassuiot/lamassuiot/shared/subsystems/v3/pkg/test/dockerrunner"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
)

func RunAWSEmulationFlociDocker(exposeAsStandardPort bool) (func() error, func() error, *AWSSDKConfig, error) {
	containerCleanup, container, dockerHost, err := dockerrunner.RunDocker(dockertest.RunOptions{
		Repository: "floci/floci", // image
		Tag:        "1.5.29",      // version
	}, func(hc *docker.HostConfig) {
		if exposeAsStandardPort {
			hc.PortBindings = map[docker.Port][]docker.PortBinding{
				"4566/tcp": {
					{
						HostIP:   "0.0.0.0",
						HostPort: "4566", // random port
					},
				},
			}
		}
	})
	if err != nil {
		return nil, nil, nil, err
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
		return nil, nil, nil, err
	}

	return func() error {
			return cleanupBeforeTest(endpoint)
		},
		containerCleanup,
		&AWSSDKConfig{
			EndpointURL:             endpoint,
			AccessKeyID:             "test",
			SecretAccessKey:         "test",
			AWSAuthenticationMethod: Static,
			Region:                  "us-east-1",
		}, nil
}

func cleanupBeforeTest(baseUrl string) error {
	// Reset Floci state before each test using the /_floci/state/reset endpoint
	// available since v1.5.29, which clears all data without restarting the container.
	url := fmt.Sprintf("%s/_floci/state/reset", baseUrl)

	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		fmt.Printf("Error creating request: %v\n", err)
		return err
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error making request: %v\n", err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code from /_floci/state/reset: %s", resp.Status)
	}

	return nil
}
