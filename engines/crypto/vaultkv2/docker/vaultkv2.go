package docker

import (
	"fmt"
	"strconv"

	"github.com/hashicorp/vault/api"
	vaultApi "github.com/hashicorp/vault/api"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	vconfig "github.com/lamassuiot/lamassuiot/engines/crypto/vaultkv2/v3/config"
	dockerrunner "github.com/lamassuiot/lamassuiot/shared/subsystems/v3/pkg/test/dockerrunner"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
)

func RunHashicorpVaultDocker(exposeAsStandardPort bool) (func() error, func() error, *vconfig.HashicorpVaultSDK, string, error) {
	rootToken := "root-token-dev"
	containerCleanup, container, _, err := dockerrunner.RunDocker(dockertest.RunOptions{
		Repository: "vault",  // image
		Tag:        "1.13.3", // version
		CapAdd:     []string{"IPC_LOCK"},
		Env: []string{
			"VAULT_DEV_ROOT_TOKEN_ID=" + rootToken,
			"VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200",
		},
		Labels: map[string]string{
			"group": "lamassuiot-monolithic",
		},
	}, func(hc *docker.HostConfig) {
		if exposeAsStandardPort {
			hc.PortBindings = map[docker.Port][]docker.PortBinding{
				"8200/tcp": {
					{
						HostIP:   "0.0.0.0",
						HostPort: "8200", // random port
					},
				},
			}
		}
	})
	if err != nil {
		return nil, nil, nil, "", err
	}

	p, _ := strconv.Atoi(container.GetPort("8200/tcp"))
	conf := vaultApi.DefaultConfig()
	conf.Address = fmt.Sprintf("http://localhost:%d", p)

	client, err := vaultApi.NewClient(conf)
	if err != nil {
		containerCleanup()
		return nil, nil, nil, "", err
	}

	healthy := false
	for !healthy {
		_, err := client.Sys().Health()
		if err == nil {
			healthy = true
		}
	}

	client.SetToken(rootToken)

	// Enable approle
	err = client.Sys().EnableAuthWithOptions("approle", &vaultApi.EnableAuthOptions{
		Type: "approle",
	})
	if err != nil {
		containerCleanup()
		return nil, nil, nil, "", err
	}

	mountPath := "lamassu-pki-kvv2"
	policyContent := fmt.Sprintf(`
	path "%s/*" {
		capabilities = [ "read", "create", "delete", "list" ]
	}  
	
	path "sys/mounts/%s" {
		capabilities = [ "read", "create", "update" ]
	}  
	
	path "sys/mounts" {
	   capabilities = [ "read" ]
	}
	`, mountPath, mountPath)
	err = client.Sys().PutPolicy("pki-kv", policyContent)
	if err != nil {
		containerCleanup()
		return nil, nil, nil, "", err
	}

	_, err = client.Logical().Write(fmt.Sprintf("auth/approle/role/%s", "lamassu-ca-client"), map[string]interface{}{
		"policies": []string{"pki-kv"},
	})
	if err != nil {
		containerCleanup()
		return nil, nil, nil, "", err
	}

	roleIDRaw, err := client.Logical().Read(fmt.Sprintf("auth/approle/role/%s/role-id", "lamassu-ca-client"))
	if err != nil {
		containerCleanup()
		return nil, nil, nil, "", err
	}

	roleID := roleIDRaw.Data["role_id"].(string)

	secretIDRAW, err := client.Logical().Write(fmt.Sprintf("auth/approle/role/%s/secret-id", "lamassu-ca-client"), nil)
	if err != nil {
		containerCleanup()
		return nil, nil, nil, "", err
	}

	secretID := secretIDRAW.Data["secret_id"].(string)

	return func() error {
			return cleanupKV2(client, mountPath)
		},
		containerCleanup, &vconfig.HashicorpVaultSDK{
			RoleID:    roleID,
			SecretID:  config.Password(secretID),
			MountPath: mountPath,
			HTTPConnection: config.HTTPConnection{
				Protocol: config.HTTP,
				BasePath: "",
				BasicConnection: config.BasicConnection{
					Hostname:  "127.0.0.1",
					Port:      p,
					TLSConfig: config.TLSConfig{},
				},
			},
		},
		rootToken,
		nil
}

func cleanupKV2(client *api.Client, path string) error {
	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return err
	}

	hasMount := false
	for mountPath := range mounts {
		if mountPath == fmt.Sprintf("%s/", path) { //mountPath has a trailing slash
			hasMount = true
		}
	}

	if hasMount {
		err := client.Sys().Unmount(path)
		if err != nil {
			return err
		}
	}

	err = client.Sys().Mount(path, &api.MountInput{
		Type: "kv-v2",
	})
	if err != nil {
		return err
	}

	return nil
}
