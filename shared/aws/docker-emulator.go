package aws

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	dockerrunner "github.com/lamassuiot/lamassuiot/shared/subsystems/v3/pkg/test/dockerrunner"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
)

func RunAWSEmulationLocalStackDocker() (func() error, func() error, *AWSSDKConfig, error) {
	containerCleanup, container, dockerHost, err := dockerrunner.RunDocker(dockertest.RunOptions{
		Repository: "localstack/localstack", // image
		Tag:        "latest",                // version
	}, func(hc *docker.HostConfig) {})
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
	// Restart localstack. This is necessary because the localstack container is reused between tests.
	// Docs say that to errase all data, a POST command can be sent to reboot and clean the data.
	url := fmt.Sprintf("%s/_localstack/health", baseUrl)
	payload := []byte(`{"action":"restart"}`)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
	if err != nil {
		fmt.Printf("Error creating request: %v\n", err)
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error making request: %v\n", err)
		return err
	}
	defer resp.Body.Close()

	// Wait for localstack to restart. We will wait 15 seconds at most.
	healthyChan := make(chan bool)
	ctxTimeout, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	checkHealth := func(respChan chan bool) {
		// If no timeout, we will wait for localstack to restart, querying its health endpoint each second
		for {
			select {
			case <-ctxTimeout.Done(): // timeout. Exit the goroutine
				return
			default:
				time.Sleep(1 * time.Second)

				req, err = http.NewRequest("GET", url, nil)
				if err != nil {
					continue
				}

				resp, err = client.Do(req)
				if err != nil {
					continue
				}

				if condition := resp.StatusCode == http.StatusOK; condition {
					respChan <- true
				}
			}
		}
	}

	go checkHealth(healthyChan)

	select {
	case <-ctxTimeout.Done():
		return fmt.Errorf("timeout waiting for localstack to restart")
	case <-healthyChan:
		return nil
	}
}
