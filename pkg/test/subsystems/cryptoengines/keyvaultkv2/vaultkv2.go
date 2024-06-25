package keyvaultkv2_test

import (
	"fmt"
	"strconv"

	vaultApi "github.com/hashicorp/vault/api"

	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/test/dockerunner"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
)

func RunHashicorpVaultDocker() (func() error, *config.HashicorpVaultSDK, string, error) {
	rootToken := "root-token-dev"
	containerCleanup, container, _, err := dockerunner.RunDocker(dockertest.RunOptions{
		Repository: "vault",  // image
		Tag:        "1.13.3", // version
		CapAdd:     []string{"IPC_LOCK"},
		Env: []string{
			"VAULT_DEV_ROOT_TOKEN_ID=" + rootToken,
			"VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200",
		},
	}, func(hc *docker.HostConfig) {
		// This function is intentionally left empty.
	})
	if err != nil {
		return nil, nil, "", err
	}

	p, _ := strconv.Atoi(container.GetPort("8200/tcp"))
	conf := vaultApi.DefaultConfig()
	conf.Address = fmt.Sprintf("http://localhost:%d", p)

	client, err := vaultApi.NewClient(conf)
	if err != nil {
		containerCleanup()
		return nil, nil, "", err
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
		return nil, nil, "", err
	}

	mountPath := "lamassu-pki-kvv2"
	policyContent := fmt.Sprintf(`
	path "%s/*" {
		capabilities = [ "read", "create", "delete" ]
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
		return nil, nil, "", err
	}

	_, err = client.Logical().Write(fmt.Sprintf("auth/approle/role/%s", "lamassu-ca-client"), map[string]interface{}{
		"policies": []string{"pki-kv"},
	})
	if err != nil {
		containerCleanup()
		return nil, nil, "", err
	}

	roleIDRaw, err := client.Logical().Read(fmt.Sprintf("auth/approle/role/%s/role-id", "lamassu-ca-client"))
	if err != nil {
		containerCleanup()
		return nil, nil, "", err
	}

	roleID := roleIDRaw.Data["role_id"].(string)

	secretIDRAW, err := client.Logical().Write(fmt.Sprintf("auth/approle/role/%s/secret-id", "lamassu-ca-client"), nil)
	if err != nil {
		containerCleanup()
		return nil, nil, "", err
	}

	secretID := secretIDRAW.Data["secret_id"].(string)

	return containerCleanup, &config.HashicorpVaultSDK{
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
	}, rootToken, nil
}
