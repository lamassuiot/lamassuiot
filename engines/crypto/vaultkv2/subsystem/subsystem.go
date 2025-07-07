package subsystem

import (
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	vconfig "github.com/lamassuiot/lamassuiot/engines/crypto/vaultkv2/v3/config"
	vault_test "github.com/lamassuiot/lamassuiot/engines/crypto/vaultkv2/v3/docker"
	"github.com/lamassuiot/lamassuiot/shared/subsystems/v3/pkg/test/subsystems"
)

func Register() {
	subsystems.RegisterSubsystemBuilder(subsystems.Vault, &VaultKV2Subsystem{})
}

type VaultKV2Subsystem struct {
}

func (p *VaultKV2Subsystem) Run(exposeAsStandardPort bool) (*subsystems.SubsystemBackend, error) {
	vaultSDKConf, vaultSuite := vault_test.BeforeSuite(exposeAsStandardPort)

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
