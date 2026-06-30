package docker

import (
	"fmt"
	"net/netip"
	"strconv"

	vaultApi "github.com/hashicorp/vault/api"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/ory/dockertest/v4"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	vconfig "github.com/lamassuiot/lamassuiot/engines/crypto/vaultkv2/v3/config"
	dockerrunner "github.com/lamassuiot/lamassuiot/shared/subsystems/v3/pkg/test/dockerrunner"
)

func RunHashicorpVaultDocker(exposeAsStandardPort bool) (func() error, func() error, *vconfig.HashicorpVaultSDK, string, error) {
	rootToken := "root-token-dev"
	runOpts := []dockertest.RunOption{
		dockertest.WithTag("1.13.3"),
		dockertest.WithHostConfig(func(config *container.HostConfig) {
			config.CapAdd = []string{"IPC_LOCK"}
		}),
		dockertest.WithEnv([]string{
			"VAULT_DEV_ROOT_TOKEN_ID=" + rootToken,
			"VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200",
		}),
		dockertest.WithLabels(map[string]string{
			"group": "lamassuiot-monolithic",
		}),
	}
	if exposeAsStandardPort {
		runOpts = append(runOpts, dockertest.WithPortBindings(network.PortMap{
			network.MustParsePort("8200/tcp"): []network.PortBinding{
				{HostIP: netip.MustParseAddr("0.0.0.0"), HostPort: "8200"},
			},
		}))
	}

	containerCleanup, container, _, err := dockerrunner.RunDocker("vault", runOpts...)
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

func cleanupKV2(client *vaultApi.Client, path string) error {
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

	err = client.Sys().Mount(path, &vaultApi.MountInput{
		Type: "kv-v2",
	})
	if err != nil {
		return err
	}

	return nil
}
