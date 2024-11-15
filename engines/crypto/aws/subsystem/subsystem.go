package subsystem

import (
	"log"

	"github.com/lamassuiot/lamassuiot/v3/core/pkg/test/subsystems"
	awskmssm_test "github.com/lamassuiot/lamassuiot/v3/engines/crypto/aws/docker"
)

func Register() {
	subsystems.RegisterSubsystemBuilder(subsystems.Aws, &AwsSubsystem{})
}

type AwsSubsystem struct {
}

func (p *AwsSubsystem) Run() (*subsystems.SubsystemBackend, error) {

	awsCleanup, awsCfg, err := awskmssm_test.RunAWSEmulationLocalStackDocker()
	if err != nil {
		log.Fatalf("could not launch AWS Platform: %s", err)
	}

	return &subsystems.SubsystemBackend{
		Config:     awsCfg,
		BeforeEach: func() error { return nil },
		AfterSuite: func() { awsCleanup() },
	}, nil

}
