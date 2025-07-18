package docker

import (
	"fmt"
	"strconv"

	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	pconfig "github.com/lamassuiot/lamassuiot/engines/crypto/pkcs11/v3/config"
	dockerrunner "github.com/lamassuiot/lamassuiot/shared/subsystems/v3/pkg/test/dockerrunner"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
)

func RunSoftHsmV2Docker(exposeAsStandardPort bool, pkcs11ProxyPath string) (func() error, func() error, pconfig.PKCS11Config, error) {
	slot := "0"
	label := "lamassuHSM"
	pin := "0123"
	sopin := "9876"
	proto := "tcp"
	containerCleanup, container, _, err := dockerrunner.RunDocker(dockertest.RunOptions{
		Repository: "ghcr.io/lamassuiot/softhsm", // image
		Tag:        "latest",                     // version
		Env: []string{
			fmt.Sprintf("SLOT=%s", slot),
			fmt.Sprintf("LABEL=%s", label),
			fmt.Sprintf("PIN=%s", pin),
			fmt.Sprintf("SO_PIN=%s", sopin),
			fmt.Sprintf("CONNECTION_PROTOCOL=%s", proto),
		},
		Labels: map[string]string{
			"group": "lamassuiot-monolithic",
		},
	}, func(hc *docker.HostConfig) {
		if exposeAsStandardPort {
			hc.PortBindings = map[docker.Port][]docker.PortBinding{
				"5657/tcp": {
					{
						HostIP:   "0.0.0.0",
						HostPort: "5657", // random port
					},
				},
			}
		}
	})
	if err != nil {
		return nil, nil, pconfig.PKCS11Config{}, err
	}

	p, _ := strconv.Atoi(container.GetPort("5657/tcp"))

	if err != nil {
		containerCleanup()
		return nil, nil, pconfig.PKCS11Config{}, err
	}

	container.Exec([]string{"sh", "-c", "apt install -y opensc"}, dockertest.ExecOptions{})

	return func() error {
			beforeEachCleanup(container)
			return nil
		},
		containerCleanup,
		pconfig.PKCS11Config{
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

func beforeEachCleanup(container *dockertest.Resource) {
	container.Exec([]string{"sh", "-c", `MODULE_PATH=/usr/local/lib/softhsm/libsofthsm2.so OBJECT_TYPES="cert privkey pubkey data" && for TYPE in $OBJECT_TYPES; do   pkcs11-tool --module "$MODULE_PATH" --list-objects --type $TYPE | grep "ID:" | awk '{print $2}' | while read ID; do     pkcs11-tool --module "$MODULE_PATH" --delete-object --type $TYPE --id $ID;   done; done`}, dockertest.ExecOptions{})
}
