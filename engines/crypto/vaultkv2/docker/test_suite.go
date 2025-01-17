package docker

import (
	"log"

	vconfig "github.com/lamassuiot/lamassuiot/engines/crypto/vaultkv2/v3/config"
)

type VaultSuite struct {
	cleanupDocker func() error
	rootToken     string
	beforeEach    func() error
}

func BeforeSuite() (vconfig.HashicorpVaultSDK, VaultSuite) {
	cleanup, beforeEach, conf, rootToken, err := RunHashicorpVaultDocker()
	if err != nil {
		log.Fatal(err)
	}

	return *conf, VaultSuite{
		cleanupDocker: cleanup,
		beforeEach:    beforeEach,
		rootToken:     rootToken,
	}
}

func (st *VaultSuite) BeforeEach() error {
	return st.beforeEach()
}

func (ts *VaultSuite) AfterSuite() {
	ts.cleanupDocker()
}

func (ts *VaultSuite) GetRootToken() string {
	return ts.rootToken
}
