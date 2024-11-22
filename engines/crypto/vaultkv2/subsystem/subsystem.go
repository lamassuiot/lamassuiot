package subsystem

import (
	"github.com/lamassuiot/lamassuiot/v3/core/pkg/config"
	vconfig "github.com/lamassuiot/lamassuiot/v3/engines/crypto/vaultkv2/config"
	vault_test "github.com/lamassuiot/lamassuiot/v3/engines/crypto/vaultkv2/docker"
	"github.com/lamassuiot/lamassuiot/v3/subsystems/pkg/test/subsystems"
)

func Register() {
	subsystems.RegisterSubsystemBuilder(subsystems.Vault, &VaultKV2Subsystem{})
}

type VaultKV2Subsystem struct {
}

func (p *VaultKV2Subsystem) Run() (*subsystems.SubsystemBackend, error) {

	vaultSDKConf, vaultSuite := vault_test.BeforeSuite()

	config, err := config.CryptoEngineConfigAdapter[vconfig.HashicorpVaultSDK]{
		ID:       "vault-1",
		Metadata: map[string]interface{}{},
		Type:     config.HashicorpVaultProvider,
		Config:   vaultSDKConf,
	}.Unmarshal()

	if err != nil {
		return nil, err
	}

	return &subsystems.SubsystemBackend{
		Config: *config,
		Extra: &map[string]interface{}{
			"rootToken": vaultSuite.GetRootToken(),
		},
		BeforeEach: vaultSuite.BeforeEach,
		AfterSuite: vaultSuite.AfterSuite,
	}, nil

}
