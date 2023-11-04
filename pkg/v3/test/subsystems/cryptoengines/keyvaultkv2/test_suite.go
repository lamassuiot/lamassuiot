package keyvaultkv2_test

import (
	"log"

	"github.com/lamassuiot/lamassuiot/pkg/v3/config"
)

var cleanupDocker func() error

func BeforeSuite() config.HashicorpVaultSDK {
	// setup *gorm.Db with docker
	cleanup, conf, err := RunHashicorpVaultDocker()
	if err != nil {
		log.Fatal(err)
	}

	cleanupDocker = cleanup
	return *conf
}

func AfterSuite() {
	cleanupDocker()
}
