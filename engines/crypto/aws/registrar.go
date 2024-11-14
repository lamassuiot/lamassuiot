package aws

import (
	cconfig "github.com/lamassuiot/lamassuiot/v3/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v3/core/pkg/engines/cryptoengines"
	aconfig "github.com/lamassuiot/lamassuiot/v3/engines/crypto/aws/config"
	log "github.com/sirupsen/logrus"
)

func RegisterAWSKMS() {
	cryptoengines.RegisterCryptoEngine(cconfig.AWSKMSProvider, func(logger *log.Entry, conf cconfig.CryptoEngine) (cryptoengines.CryptoEngine, error) {

		ceConfig, _ := cconfig.DecodeStruct[aconfig.AWSCryptoEngine](conf.Config)

		awsCfg, err := cconfig.GetAwsSdkConfig(ceConfig.AWSSDKConfig)
		if err != nil {
			log.Warnf("skipping AWS KMS engine with id %s: %s", conf.ID, err)
		}

		return NewAWSKMSEngine(logger, *awsCfg, conf.Metadata)
	})
}

func RegisterAWSSecrets() {
	cryptoengines.RegisterCryptoEngine(cconfig.AWSSecretsManagerProvider, func(logger *log.Entry, conf cconfig.CryptoEngine) (cryptoengines.CryptoEngine, error) {

		ceConfig, _ := cconfig.DecodeStruct[aconfig.AWSCryptoEngine](conf.Config)

		awsCfg, err := cconfig.GetAwsSdkConfig(ceConfig.AWSSDKConfig)
		if err != nil {
			log.Warnf("skipping AWS Sercrets Manager engine with id %s: %s", conf.ID, err)
		}

		return NewAWSSecretManagerEngine(logger, *awsCfg, conf.Metadata)
	})
}
