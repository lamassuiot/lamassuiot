package azure

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	dockerrunner "github.com/lamassuiot/lamassuiot/shared/subsystems/v3/pkg/test/dockerrunner"
	"github.com/moby/moby/api/types/network"
	"github.com/ory/dockertest/v4"
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
	runOpts := []dockertest.RunOption{
		dockertest.WithTag("0.8.0"),
	}
	if exposeAsStandardPort {
		runOpts = append(runOpts, dockertest.WithPortBindings(network.PortMap{
			network.MustParsePort("4577/tcp"): []network.PortBinding{
				{HostIP: netip.MustParseAddr("0.0.0.0"), HostPort: "4577"},
			},
		}))
	}
	containerCleanup, container, dockerHost, err := dockerrunner.RunDocker("floci/floci-az", runOpts...)
	if err != nil {
		return nil, nil, nil, err
	}

	p, _ := strconv.Atoi(container.GetPort("4577/tcp"))
	endpoint := fmt.Sprintf("http://127.0.0.1:%d", p)

	// Retry until the emulator is ready to handle requests.
	err = dockerHost.Retry(context.Background(), time.Minute, func() error {
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
