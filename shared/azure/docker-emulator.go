package azure

import (
	"fmt"
	"net/http"
	"strconv"

	dockerrunner "github.com/lamassuiot/lamassuiot/shared/subsystems/v3/pkg/test/dockerrunner"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
)

const (
	// Standard Azure Storage emulator account credentials — accepted by floci-az in dev mode.
	EmulatorAccountName = "devstoreaccount1"
	EmulatorAccountKey  = "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMh0=="
)

// RunAzureEmulationFlociAZDocker starts a floci-az container and waits until it is
// ready to serve requests. It returns two cleanup functions (pre-test cleanup and
// container teardown) plus a populated AzureSDKConfig that callers can use to
// build Azure SDK clients against the emulator.
func RunAzureEmulationFlociAZDocker(exposeAsStandardPort bool) (func() error, func() error, *AzureSDKConfig, error) {
	containerCleanup, container, dockerHost, err := dockerrunner.RunDocker(dockertest.RunOptions{
		Repository: "floci/floci-az",
		Tag:        "0.8.0",
	}, func(hc *docker.HostConfig) {
		if exposeAsStandardPort {
			hc.PortBindings = map[docker.Port][]docker.PortBinding{
				"4577/tcp": {
					{
						HostIP:   "0.0.0.0",
						HostPort: "4577",
					},
				},
			}
		}
	})
	if err != nil {
		return nil, nil, nil, err
	}

	p, _ := strconv.Atoi(container.GetPort("4577/tcp"))
	endpoint := fmt.Sprintf("http://127.0.0.1:%d", p)

	// Retry until the emulator is ready to handle requests.
	err = dockerHost.Retry(func() error {
		r, err := http.DefaultClient.Get(endpoint)
		if err != nil {
			return err
		}
		defer r.Body.Close()

		if r.StatusCode != http.StatusOK {
			return fmt.Errorf("unexpected status code %s", r.Status)
		}

		return nil
	})
	if err != nil {
		containerCleanup()
		return nil, nil, nil, err
	}

	return func() error { return nil },
		containerCleanup,
		&AzureSDKConfig{
			AzureAuthenticationMethod: Emulator,
			VaultURL:                  endpoint + "/" + EmulatorAccountName + "-keyvault",
			AllowHTTP:                 true,
		}, nil
}
