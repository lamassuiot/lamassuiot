package config

import (
	cconfig "github.com/lamassuiot/lamassuiot/v2/core/pkg/config"
	"github.com/sirupsen/logrus"
)

type CAConfig struct {
	Logs              BaseConfigLogging              `mapstructure:"logs"`
	Server            HttpServer                     `mapstructure:"server"`
	PublisherEventBus EventBusEngine                 `mapstructure:"publisher_event_bus"`
	Storage           cconfig.PluggableStorageEngine `mapstructure:"storage"`
	CryptoEngines     CryptoEngines                  `mapstructure:"crypto_engines"`
	CryptoMonitoring  CryptoMonitoring               `mapstructure:"crypto_monitoring"`
	VAServerDomain    string                         `mapstructure:"va_server_domain"`
}

type CryptoEngines struct {
	LogLevel                  cconfig.LogLevel                           `mapstructure:"log_level"`
	DefaultEngine             string                                     `mapstructure:"default_id"`
	PKCS11Provider            []cconfig.PKCS11EngineConfig               `mapstructure:"pkcs11"`
	HashicorpVaultKV2Provider []cconfig.HashicorpVaultCryptoEngineConfig `mapstructure:"hashicorp_vault"`
	AWSKMSProvider            []cconfig.AWSCryptoEngine                  `mapstructure:"aws_kms"`
	AWSSecretsManagerProvider []cconfig.AWSCryptoEngine                  `mapstructure:"aws_secrets_manager"`
	FilesystemProvider        []cconfig.FilesystemEngineConfig           `mapstructure:"golang"`
	CryptoEngines             []cconfig.CryptoEngine                     `mapstructure:"crypto_engines"`
}

type CryptoMonitoring struct {
	Enabled   bool   `mapstructure:"enabled"`
	Frequency string `mapstructure:"frequency"`
}

func MigrateCryptoEnginesToV2Config(logger *logrus.Entry, config CAConfig) CAConfig {

	// Migrate CryptoEngines to V2
	// Process each crypto engine config an convert into the new format CryptoEngine
	// This is done to ensure that the config is backward compatible with the previous version
	// of the config

	if len(config.CryptoEngines.CryptoEngines) > 0 {
		return config
	}

	logger.Warn("Old crypto engine config detected this is deprecated and will be removed in the future")
	logger.Warn("Please update your configuration to the new format")

	// Create a new slice to hold the new crypto engines
	newCryptoEngines := make([]cconfig.CryptoEngine, 0)
	// Iterate over the crypto engines of type PKCS11
	for _, pkcs11Engine := range config.CryptoEngines.PKCS11Provider {
		newCryptoEngines = addCryptoEngine[cconfig.PKCS11EngineConfig](cconfig.PKCS11Provider, pkcs11Engine, newCryptoEngines)
	}

	// Iterate over the crypto engines of type HashicorpVault
	for _, hashicorpVaultEngine := range config.CryptoEngines.HashicorpVaultKV2Provider {
		newCryptoEngines = addCryptoEngine[cconfig.HashicorpVaultCryptoEngineConfig](cconfig.HashicorpVaultProvider, hashicorpVaultEngine, newCryptoEngines)
	}

	// Iterate over the crypto engines of type AWSKMS
	for _, awsKmsEngine := range config.CryptoEngines.AWSKMSProvider {
		newCryptoEngines = addCryptoEngine[cconfig.AWSCryptoEngine](cconfig.AWSKMSProvider, awsKmsEngine, newCryptoEngines)
	}

	// Iterate over the crypto engines of type AWSSecretsManager
	for _, awsSecretsManagerEngine := range config.CryptoEngines.AWSSecretsManagerProvider {
		newCryptoEngines = addCryptoEngine[cconfig.AWSCryptoEngine](cconfig.AWSSecretsManagerProvider, awsSecretsManagerEngine, newCryptoEngines)
	}

	// Iterate over the crypto engines of type Golang
	for _, golangEngine := range config.CryptoEngines.FilesystemProvider {
		newCryptoEngines = addCryptoEngine[cconfig.FilesystemEngineConfig](cconfig.FilesystemProvider, golangEngine, newCryptoEngines)
	}

	// Clear old config
	config.CryptoEngines.PKCS11Provider = nil
	config.CryptoEngines.HashicorpVaultKV2Provider = nil
	config.CryptoEngines.AWSSecretsManagerProvider = nil
	config.CryptoEngines.AWSKMSProvider = nil
	config.CryptoEngines.FilesystemProvider = nil

	config.CryptoEngines.CryptoEngines = newCryptoEngines

	return config
}

func addCryptoEngine[E any](provider cconfig.CryptoEngineProvider, config E, newCryptoEngines []cconfig.CryptoEngine) []cconfig.CryptoEngine {
	encoded, err := cconfig.EncodeStruct(config)
	if err != nil {
		panic(err)
	}

	delete(encoded, "id")
	delete(encoded, "metadata")

	var id string
	var metadata map[string]interface{}

	switch t := any(config).(type) {
	case cconfig.PKCS11EngineConfig:
		id = t.ID
		metadata = t.Metadata
	case cconfig.HashicorpVaultCryptoEngineConfig:
		id = t.ID
		metadata = t.Metadata
	case cconfig.AWSCryptoEngine:
		id = t.ID
		metadata = t.Metadata
	case cconfig.FilesystemEngineConfig:
		id = t.ID
		metadata = t.Metadata
	default:
		panic("Unrecognized config type")
	}

	newCryptoEngines = append(newCryptoEngines, cconfig.CryptoEngine{
		ID:       id,
		Metadata: metadata,
		Type:     provider,
		Config:   encoded,
	})
	return newCryptoEngines
}
