package subsystem

import (
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	pconfig "github.com/lamassuiot/lamassuiot/engines/crypto/pkcs11/v3/config"
	"github.com/lamassuiot/lamassuiot/engines/crypto/pkcs11/v3/docker"
	"github.com/lamassuiot/lamassuiot/shared/subsystems/v3/pkg/test/subsystems"
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

func (p *Pkcs11Subsystem) Run(exposeAsStandardPort bool) (*subsystems.SubsystemBackend, error) {
	_, softhsmCleanup, pkcs11Cfg, err := docker.RunSoftHsmV2Docker(exposeAsStandardPort, p.hsmModulePath)
	if err != nil {
		return nil, err
	}

	configAdapter := config.CryptoEngineConfigAdapter[pconfig.PKCS11Config]{
		ID:       "pkcs11-1",
		Metadata: map[string]interface{}{},
		Type:     config.PKCS11Provider,
		Config:   pkcs11Cfg,
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
