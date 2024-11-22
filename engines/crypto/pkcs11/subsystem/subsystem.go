package subsystem

import (
	"github.com/lamassuiot/lamassuiot/v3/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v3/engines/crypto/pkcs11"
	pkcs11_test "github.com/lamassuiot/lamassuiot/v3/engines/crypto/pkcs11/test"
	"github.com/lamassuiot/lamassuiot/v3/subsystems/pkg/test/subsystems"
)

func Register() {
	subsystems.RegisterSubsystemBuilder(subsystems.Pkcs11, &Pkcs11Subsystem{})
}

type Pkcs11Subsystem struct {
	hsmModulePath string
}

func (p *Pkcs11Subsystem) Prepare(config map[string]interface{}) error {
	p.hsmModulePath = config["hsmModulePath"].(string)
	return nil
}

func (p *Pkcs11Subsystem) Run() (*subsystems.SubsystemBackend, error) {

	softhsmCleanup, pkcs11Cfg, err := pkcs11_test.RunSoftHsmV2Docker(p.hsmModulePath)
	if err != nil {
		return nil, err
	}

	configAdapter := config.CryptoEngineConfigAdapter[pkcs11.PKCS11Config]{
		ID:       "pkcs11-1",
		Metadata: map[string]interface{}{},
		Type:     config.PKCS11Provider,
		Config:   *pkcs11Cfg,
	}

	config, err := configAdapter.Unmarshal()
	if err != nil {
		return nil, err
	}

	return &subsystems.SubsystemBackend{
		Config:     *config,
		BeforeEach: func() error { return nil },
		AfterSuite: func() { softhsmCleanup() },
	}, nil

}
