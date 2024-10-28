package docker

import (
	"log"

	"github.com/lamassuiot/lamassuiot/v2/core/pkg/config"
)

type VaultSuite struct {
	cleanupDocker func() error
	rootToken     string
}

func BeforeSuite() (config.HashicorpVaultSDK, VaultSuite) {
	// setup *gorm.Db with docker
	cleanup, conf, rootToken, err := RunHashicorpVaultDocker()
	if err != nil {
		log.Fatal(err)
	}

	return *conf, VaultSuite{
		cleanupDocker: cleanup,
		rootToken:     rootToken,
	}
}

func (st *VaultSuite) BeforeEach() error {
	// clear db tables before each test
	return nil
}

func (ts *VaultSuite) AfterSuite() {
	ts.cleanupDocker()
}

func (ts *VaultSuite) GetRootToken() string {
	return ts.rootToken
}
