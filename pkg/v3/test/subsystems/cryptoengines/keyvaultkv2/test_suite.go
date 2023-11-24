package keyvaultkv2_test

import (
	"log"

	"github.com/lamassuiot/lamassuiot/pkg/v3/config"
)

type VaultSuite struct {
	cleanupDocker func() error
}

func BeforeSuite() (config.HashicorpVaultSDK, VaultSuite) {
	// setup *gorm.Db with docker
	cleanup, conf, _, err := RunHashicorpVaultDocker()
	if err != nil {
		log.Fatal(err)
	}

	return *conf, VaultSuite{
		cleanupDocker: cleanup,
	}
}

func (st *VaultSuite) BeforeEach() error {
	// clear db tables before each test
	return nil
}

func (ts *VaultSuite) AfterSuite() {
	ts.cleanupDocker()
}
