package keyvaultkv2_test

import (
	"fmt"
	"log"
	"strconv"

	"github.com/hashicorp/vault/api"
	vaultApi "github.com/hashicorp/vault/api"

	"github.com/lamassuiot/lamassuiot/pkg/v3/config"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
)

var cleanupDocker func()

func BeforeSuite() config.HashicorpVaultSDK {
	// setup *gorm.Db with docker
	var conf config.HashicorpVaultSDK
	cleanupDocker, conf = SetupVaultWithDocker()
	return conf
}

func AfterSuite() {
	cleanupDocker()
}

func SetupVaultWithDocker() (func(), config.HashicorpVaultSDK) {
	pool, err := dockertest.NewPool("")
	chk(err)

	rootToken := "root-token-dev"
	runDockerOpt := &dockertest.RunOptions{
		Repository: "vault",  // image
		Tag:        "1.13.3", // version
		CapAdd:     []string{"IPC_LOCK"},
		Env: []string{
			"VAULT_DEV_ROOT_TOKEN_ID=" + rootToken,
			"VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200",
		},
	}

	fnConfig := func(config *docker.HostConfig) {
		config.AutoRemove = true                     // set AutoRemove to true so that stopped container goes away by itself
		config.RestartPolicy = docker.NeverRestart() // don't restart container
	}

	resource, err := pool.RunWithOptions(runDockerOpt, fnConfig)
	chk(err)
	// call clean up function to release resource
	fnCleanup := func() {
		err := resource.Close()
		chk(err)
	}

	p, _ := strconv.Atoi(resource.GetPort("8200/tcp"))
	conf := vaultApi.DefaultConfig()
	conf.Address = fmt.Sprintf("http://localhost:%d", p)

	client, err := vaultApi.NewClient(conf)
	chk(err)

	healthy := false
	for !healthy {
		r, err := client.Sys().Health()
		if err == nil {
			fmt.Println(r)
			healthy = true
		}
	}

	client.SetToken(rootToken)

	// Enable approle
	err = client.Sys().EnableAuthWithOptions("approle", &api.EnableAuthOptions{
		Type: "approle",
	})
	chk(err)

	mountPath := "lamassu-pki-kvv2"
	policyContent := fmt.Sprintf(`
	path "%s/*" {
		capabilities = [ "read", "create" ]
	}  
	
	path "sys/mounts/%s" {
		capabilities = [ "read", "create", "update" ]
	}  
	
	path "sys/mounts" {
	   capabilities = [ "read" ]
	}
	`, mountPath, mountPath)
	err = client.Sys().PutPolicy("pki-kv", policyContent)
	chk(err)

	_, err = client.Logical().Write(fmt.Sprintf("auth/approle/role/%s", "lamassu-ca-client"), map[string]interface{}{
		"policies": []string{"pki-kv"},
	})
	chk(err)

	roleIDRaw, err := client.Logical().Read(fmt.Sprintf("auth/approle/role/%s/role-id", "lamassu-ca-client"))
	chk(err)

	roleID := roleIDRaw.Data["role_id"].(string)

	secretIDRAW, err := client.Logical().Write(fmt.Sprintf("auth/approle/role/%s/secret-id", "lamassu-ca-client"), nil)
	chk(err)

	secretID := secretIDRAW.Data["secret_id"].(string)

	return fnCleanup, config.HashicorpVaultSDK{
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
	}
}

func chk(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
