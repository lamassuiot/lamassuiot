package docker

import (
	"log"

	vconfig "github.com/lamassuiot/lamassuiot/pki/v3/engines/crypto/vaultkv2/config"
)

type VaultSuite struct {
	cleanupDocker func() error
	rootToken     string
	beforeEach    func() error
}

func BeforeSuite(exposeAsStandardPort bool) (vconfig.HashicorpVaultSDK, VaultSuite) {
	beforeEach, cleanup, conf, rootToken, err := RunHashicorpVaultDocker(exposeAsStandardPort)
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
