package subsystem

import (
	"github.com/lamassuiot/lamassuiot/v3/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v3/core/pkg/test/subsystems"
	vault_test "github.com/lamassuiot/lamassuiot/v3/engines/crypto/vaultkv2/docker"
)

func Register() {
	subsystems.RegisterSubsystemBuilder(subsystems.Vault, &VaultKV2Subsystem{})
}

type VaultKV2Subsystem struct {
}

func (p *VaultKV2Subsystem) Run() (*subsystems.SubsystemBackend, error) {

	vaultSDKConf, vaultSuite := vault_test.BeforeSuite()

	vaultConfig, err := config.EncodeStruct(vaultSDKConf)
	if err != nil {
		return nil, err
	}

	config := config.CryptoEngine[any]{
		ID:       "vault-1",
		Metadata: map[string]interface{}{},
		Type:     config.HashicorpVaultProvider,
		Config:   vaultConfig,
	}

	return &subsystems.SubsystemBackend{
		Config: config,
		Extra: &map[string]interface{}{
			"rootToken": vaultSuite.GetRootToken(),
		},
		BeforeEach: vaultSuite.BeforeEach,
		AfterSuite: vaultSuite.AfterSuite,
	}, nil

}
