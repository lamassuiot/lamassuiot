package keyvaultkv2_test

import (
	"fmt"
	"log"
	"strconv"

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

	// Create AppRole
	client.SetToken(rootToken)
	s, err := client.Logical().Write("auth/approle/role/lamassu-ca-client", map[string]interface{}{
		"backend":                 "approle",
		"role_name":               "lamassu-ca",
		"token_policies":          []string{"lamassu-ca"},
		"token_no_default_policy": "true",
		"bind_secret_id":          "true",
		"token_period":            "0",
	})
	if err != nil {
		chk(err)
	}

	fmt.Println(s)
	secret, err := client.Logical().Write("auth/approle/role/lamassu-ca-client/secret-id", map[string]interface{}{
		"secret_id": "secret_id_value",
	})
	if err != nil {
		chk(err)
	}

	secretID := secret.Data["secret_id"].(string)
	fmt.Println(secretID)
	_, err = client.Logical().Write("auth/approle/role/lamassu-ca-client/role-id", map[string]interface{}{
		"role_id": "role_id_value",
	})
	if err != nil {
		chk(err)
	}

	// container is ready, return *gorm.Db for testing
	return fnCleanup, config.HashicorpVaultSDK{
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
