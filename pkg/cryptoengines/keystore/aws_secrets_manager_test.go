package keystore

import (
	"fmt"

	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/helpers"
	awskmssm_test "github.com/lamassuiot/lamassuiot/v2/pkg/test/subsystems/cryptoengines/aws-kms-sm"
)

func setupAWSSecretManagerKeyProvider() keystoreTestProvider {
	// Create a new instance of GoCryptoEngine
	return keystoreTestProvider{
		Setup: func() (KeyStore, func(), error) {
			log := helpers.SetupLogger(config.Info, "CA TestCase", "Golang Engine")

			teardown, awsSdkCfg, err := awskmssm_test.RunAWSEmulationLocalStackDocker()
			if err != nil {
				return nil, nil, fmt.Errorf("could not start localstack: %s", err)
			}

			awsCfg, err := config.GetAwsSdkConfig(*awsSdkCfg)
			if err != nil {
				return nil, nil, fmt.Errorf("could not get aws sdk config: %s", err)
			}

			engine, err := NewAWSSecretManagerKeyStorage(log, *awsCfg)
			if err != nil {
				return nil, nil, fmt.Errorf("could not create the AWS Secrets Manager Key Storage: %s", err)
			}

			return engine, func() {
				teardown()
			}, err
		},
	}
}
