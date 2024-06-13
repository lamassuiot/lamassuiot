package keystore

import (
	"context"
	"fmt"
	"net"

	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/helpers"
	awskmssm_test "github.com/lamassuiot/lamassuiot/v2/pkg/test/subsystems/cryptoengines/aws-kms-sm"
)

type CustomResolver struct {
	*net.Resolver
}

func (r *CustomResolver) LookupIP(host string) ([]net.IP, error) {
	if host == "example.com" {
		// Return the desired IP address for the specific domain
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	}

	// Use the default resolver for other domains
	return r.Resolver.LookupIP(context.Background(), "ip", host)
}

func setupS3KeyProvider() keystoreTestProvider {
	// Create a new instance of GoCryptoEngine
	return keystoreTestProvider{
		Setup: func() (KeyStore, func(), error) {
			log := helpers.SetupLogger(config.Info, "CA TestCase", "Golang Engine")
			bucketName := "my-bucket"

			teardown, awsSdkCfg, err := awskmssm_test.RunAWSEmulationLocalStackDocker()
			if err != nil {
				return nil, nil, fmt.Errorf("could not start localstack: %s", err)
			}

			awsCfg, err := config.GetAwsSdkConfig(*awsSdkCfg)
			if err != nil {
				return nil, nil, fmt.Errorf("could not get aws sdk config: %s", err)
			}

			engine, err := NewS3Storager(log, *awsCfg, bucketName)
			if err != nil {
				return nil, nil, fmt.Errorf("could not create the S3 Key Storage: %s", err)
			}

			return engine, func() {
				teardown()
			}, nil
		},
	}
}
