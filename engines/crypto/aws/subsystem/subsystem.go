package subsystem

import (
	"log"

	"github.com/lamassuiot/lamassuiot/v3/aws"
	"github.com/lamassuiot/lamassuiot/v3/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v3/core/pkg/test/subsystems"
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

	configMap, err := config.EncodeStruct(awsCfg)
	if err != nil {
		log.Fatalf("could not encode AWS Platform config: %s", err)
	}

	cryptoEngine := config.CryptoEngine[any]{
		ID:       "aws-1",
		Metadata: make(map[string]interface{}),
		Type:     config.AWSKMSProvider,
		Config:   configMap,
	}

	return &subsystems.SubsystemBackend{
		Config:     cryptoEngine,
		BeforeEach: func() error { return nil },
		AfterSuite: func() { awsCleanup() },
	}, nil

}
