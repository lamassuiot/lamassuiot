package aws

import (
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines"
	laws "github.com/lamassuiot/lamassuiot/shared/aws/v3"
	log "github.com/sirupsen/logrus"
)

func RegisterAWSKMS() {
	cryptoengines.RegisterCryptoEngine(cconfig.AWSKMSProvider, func(logger *log.Entry, conf cconfig.CryptoEngineConfig) (cryptoengines.CryptoEngine, error) {
		ceConfig, _ := cconfig.DecodeStruct[AWSCryptoEngine](conf.Config)

		awsCfg, err := laws.GetAwsSdkConfig(ceConfig.AWSSDKConfig)
		if err != nil {
			log.Warnf("skipping AWS KMS engine with id %s: %s", conf.ID, err)
		}

		return NewAWSKMSEngine(logger, *awsCfg, conf.Metadata)
	})
}

func RegisterAWSSecrets() {
	cryptoengines.RegisterCryptoEngine(cconfig.AWSSecretsManagerProvider, func(logger *log.Entry, conf cconfig.CryptoEngineConfig) (cryptoengines.CryptoEngine, error) {
		ceConfig, _ := cconfig.DecodeStruct[AWSCryptoEngine](conf.Config)

		awsCfg, err := laws.GetAwsSdkConfig(ceConfig.AWSSDKConfig)
		if err != nil {
			log.Warnf("skipping AWS Sercrets Manager engine with id %s: %s", conf.ID, err)
		}

		return NewAWSSecretManagerEngine(logger, *awsCfg, conf.Metadata)
	})
}
