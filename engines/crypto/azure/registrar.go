package azure

import (
	cconfig "github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/cryptoengines"
	lazure "github.com/lamassuiot/lamassuiot/v4/shared/azure"
	log "github.com/sirupsen/logrus"
)

func RegisterAzureKeyVault() {
	cryptoengines.RegisterCryptoEngine(cconfig.AzureKeyVaultProvider, func(logger *log.Entry, conf cconfig.CryptoEngineConfig) (cryptoengines.CryptoEngine, error) {
		ceConfig, _ := cconfig.DecodeStruct[AzureCryptoEngine](conf.Config)

		credential, err := lazure.GetAzureCredential(ceConfig.AzureSDKConfig)
		if err != nil {
			logger.Warnf("skipping Azure Key Vault engine with id %s: %s", conf.ID, err)
			return nil, err
		}

		return NewAzureKeyVaultEngine(logger, ceConfig.VaultURL, credential, ceConfig.AllowHTTP, conf.Metadata)
	})
}

func RegisterAzureSecrets() {
	cryptoengines.RegisterCryptoEngine(cconfig.AzureKeyVaultSecretsProvider, func(logger *log.Entry, conf cconfig.CryptoEngineConfig) (cryptoengines.CryptoEngine, error) {
		ceConfig, _ := cconfig.DecodeStruct[AzureCryptoEngine](conf.Config)

		credential, err := lazure.GetAzureCredential(ceConfig.AzureSDKConfig)
		if err != nil {
			logger.Warnf("skipping Azure Key Vault Secrets engine with id %s: %s", conf.ID, err)
			return nil, err
		}

		return NewAzureKeyVaultSecretsEngine(logger, ceConfig.VaultURL, credential, ceConfig.AllowHTTP, conf.Metadata)
	})
}
