package subsystem

import (
	"log"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/shared/azure/v3"
	"github.com/lamassuiot/lamassuiot/shared/subsystems/v3/pkg/test/subsystems"
)

func Register() {
	subsystems.RegisterSubsystemBuilder(subsystems.Azure, &AzureSubsystem{})
}

type AzureSubsystem struct {
}

func (p *AzureSubsystem) Run(exposeAsStandardPort bool) (*subsystems.SubsystemBackend, error) {
	azureCleanup, _, azureCfg, err := azure.RunAzureEmulationFlociAZDocker(exposeAsStandardPort)
	if err != nil {
		log.Fatalf("could not launch Azure Platform: %s", err)
	}

	cryptoEngine, err := config.CryptoEngineConfigAdapter[azure.AzureSDKConfig]{
		ID:       "azure-1",
		Metadata: make(map[string]interface{}),
		Type:     config.AzureKeyVaultProvider,
		Config:   *azureCfg,
	}.Unmarshal()

	if err != nil {
		log.Fatalf("could not marshal Azure Platform config: %s", err)
	}

	return &subsystems.SubsystemBackend{
		Config:     *cryptoEngine,
		BeforeEach: func() error { return nil },
		AfterSuite: func() { azureCleanup() },
	}, nil

}
