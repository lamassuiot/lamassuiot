package aws

import (
	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/cryptoengines"
	log "github.com/sirupsen/logrus"
)

func RegisterAWSKMS() {
	cryptoengines.RegisterCryptoEngine(config.AWSKMSProvider, func(logger *log.Entry, conf config.CryptoEngine) (cryptoengines.CryptoEngine, error) {
		var ceConfig config.AWSCryptoEngine
		config.DecodeStruct(conf.Config, &ceConfig)

		awsCfg, err := config.GetAwsSdkConfig(ceConfig.AWSSDKConfig)
		if err != nil {
			log.Warnf("skipping AWS KMS engine with id %s: %s", conf.ID, err)
		}

		return NewAWSKMSEngine(logger, *awsCfg, conf.Metadata)
	})
}

func RegisterAWSSecrets() {
	cryptoengines.RegisterCryptoEngine(config.AWSSecretsManagerProvider, func(logger *log.Entry, conf config.CryptoEngine) (cryptoengines.CryptoEngine, error) {
		var ceConfig config.AWSCryptoEngine
		config.DecodeStruct(conf.Config, &ceConfig)

		awsCfg, err := config.GetAwsSdkConfig(ceConfig.AWSSDKConfig)
		if err != nil {
			log.Warnf("skipping AWS KMS engine with id %s: %s", conf.ID, err)
		}

		return NewAWSSecretManagerEngine(logger, *awsCfg, conf.Metadata)
	})
}
