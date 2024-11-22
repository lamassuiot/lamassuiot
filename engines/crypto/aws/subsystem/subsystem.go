package subsystem

import (
	"log"

	"github.com/lamassuiot/lamassuiot/v3/aws"
	"github.com/lamassuiot/lamassuiot/v3/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v3/subsystems/pkg/test/subsystems"
)

func Register() {
	subsystems.RegisterSubsystemBuilder(subsystems.Aws, &AwsSubsystem{})
}

type AwsSubsystem struct {
}

func (p *AwsSubsystem) Run() (*subsystems.SubsystemBackend, error) {

	awsCleanup, awsCfg, err := aws.RunAWSEmulationLocalStackDocker()
	if err != nil {
		log.Fatalf("could not launch AWS Platform: %s", err)
	}

	cryptoEngine, err := config.CryptoEngineConfigAdapter[aws.AWSSDKConfig]{
		ID:       "aws-1",
		Metadata: make(map[string]interface{}),
		Type:     config.AWSKMSProvider,
		Config:   *awsCfg,
	}.Unmarshal()

	if err != nil {
		log.Fatalf("could not marshal AWS Platform config: %s", err)
	}

	return &subsystems.SubsystemBackend{
		Config:     *cryptoEngine,
		BeforeEach: func() error { return nil },
		AfterSuite: func() { awsCleanup() },
	}, nil

}
