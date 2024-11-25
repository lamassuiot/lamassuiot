package softhsmv2_test

import (
	"fmt"
	"strconv"

	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	pconfig "github.com/lamassuiot/lamassuiot/engines/crypto/pkcs11/v3"
	dockerunner "github.com/lamassuiot/lamassuiot/shared/subsystems/v3/pkg/test/dockerrunner"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
)

func RunSoftHsmV2Docker(pkcs11ProxyPath string) (func() error, *pconfig.PKCS11Config, error) {
	slot := "0"
	label := "lamassuHSM"
	pin := "0123"
	sopin := "9876"
	proto := "tcp"
	containerCleanup, container, _, err := dockerunner.RunDocker(dockertest.RunOptions{
		Repository: "ghcr.io/lamassuiot/softhsm", // image
		Tag:        "latest",                     // version
		Env: []string{
			fmt.Sprintf("SLOT=%s", slot),
			fmt.Sprintf("LABEL=%s", label),
			fmt.Sprintf("PIN=%s", pin),
			fmt.Sprintf("SO_PIN=%s", sopin),
			fmt.Sprintf("CONNECTION_PROTOCOL=%s", proto),
		},
	}, func(hc *docker.HostConfig) {})
	if err != nil {
		return nil, nil, err
	}

	p, _ := strconv.Atoi(container.GetPort("5657/tcp"))

	if err != nil {
		containerCleanup()
		return nil, nil, err
	}

	return containerCleanup, &pconfig.PKCS11Config{
		TokenLabel: label,
		TokenPin:   cconfig.Password(pin),
		ModulePath: pkcs11ProxyPath,
		ModuleExtraOptions: pconfig.PKCS11ModuleExtraOptions{
			Env: map[string]string{
				"PKCS11_PROXY_SOCKET": fmt.Sprintf("%s://0.0.0.0:%d", proto, p),
			},
		},
	}, nil
}
