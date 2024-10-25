package config

import "github.com/sirupsen/logrus"

type CAConfig struct {
	Logs              BaseConfigLogging      `mapstructure:"logs"`
	Server            HttpServer             `mapstructure:"server"`
	PublisherEventBus EventBusEngine         `mapstructure:"publisher_event_bus"`
	Storage           PluggableStorageEngine `mapstructure:"storage"`
	CryptoEngines     CryptoEngines          `mapstructure:"crypto_engines"`
	CryptoMonitoring  CryptoMonitoring       `mapstructure:"crypto_monitoring"`
	VAServerDomain    string                 `mapstructure:"va_server_domain"`
}

type CryptoEngines struct {
	LogLevel                  LogLevel                           `mapstructure:"log_level"`
	DefaultEngine             string                             `mapstructure:"default_id"`
	PKCS11Provider            []PKCS11EngineConfig               `mapstructure:"pkcs11"`
	HashicorpVaultKV2Provider []HashicorpVaultCryptoEngineConfig `mapstructure:"hashicorp_vault"`
	AWSKMSProvider            []AWSCryptoEngine                  `mapstructure:"aws_kms"`
	AWSSecretsManagerProvider []AWSCryptoEngine                  `mapstructure:"aws_secrets_manager"`
	FilesystemProvider        []FilesystemEngineConfig           `mapstructure:"golang"`
	CryptoEngines             []CryptoEngine                     `mapstructure:"crypto_engines"`
}

type CryptoEngine struct {
	ID       string                 `mapstructure:"id"`
	Metadata map[string]interface{} `mapstructure:"metadata"`
	Type     CryptoEngineProvider   `mapstructure:"type"`
	Config   map[string]interface{} `mapstructure:",remain"`
}

type HashicorpVaultCryptoEngineConfig struct {
	HashicorpVaultSDK `mapstructure:",squash"`
	ID                string                 `mapstructure:"id"`
	Metadata          map[string]interface{} `mapstructure:"metadata"`
}
type HashicorpVaultSDK struct {
	RoleID            string     `mapstructure:"role_id"`
	SecretID          Password   `mapstructure:"secret_id"`
	AutoUnsealEnabled bool       `mapstructure:"auto_unseal_enabled"`
	AutoUnsealKeys    []Password `mapstructure:"auto_unseal_keys"`
	MountPath         string     `mapstructure:"mount_path"`
	HTTPConnection    `mapstructure:",squash"`
}

type FilesystemEngineConfig struct {
	ID               string                 `mapstructure:"id"`
	Metadata         map[string]interface{} `mapstructure:"metadata"`
	StorageDirectory string                 `mapstructure:"storage_directory"`
}

type PKCS11Config struct {
	TokenLabel         string                   `mapstructure:"token"`
	TokenPin           Password                 `mapstructure:"pin"`
	ModulePath         string                   `mapstructure:"module_path"`
	ModuleExtraOptions PKCS11ModuleExtraOptions `mapstructure:"module_extra_options"`
}

type PKCS11EngineConfig struct {
	PKCS11Config `mapstructure:",squash"`
	ID           string                 `mapstructure:"id"`
	Metadata     map[string]interface{} `mapstructure:"metadata"`
}

type PKCS11ModuleExtraOptions struct {
	Env map[string]string `mapstructure:"env"`
}

type AWSCryptoEngine struct {
	AWSSDKConfig `mapstructure:",squash"`
	ID           string                 `mapstructure:"id"`
	Metadata     map[string]interface{} `mapstructure:"metadata"`
}

type AWSSDKConfig struct {
	AWSAuthenticationMethod AWSAuthenticationMethod `mapstructure:"auth_method"`
	EndpointURL             string                  `mapstructure:"endpoint_url"`
	AccessKeyID             string                  `mapstructure:"access_key_id"`
	SecretAccessKey         Password                `mapstructure:"secret_access_key"`
	SessionToken            Password                `mapstructure:"session_token"`
	Region                  string                  `mapstructure:"region"`
	RoleARN                 string                  `mapstructure:"role_arn"`
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
	newCryptoEngines := make([]CryptoEngine, 0)
	// Iterate over the crypto engines of type PKCS11
	for _, pkcs11Engine := range config.CryptoEngines.PKCS11Provider {
		newCryptoEngines = addCryptoEngine[PKCS11EngineConfig](PKCS11Provider, pkcs11Engine, newCryptoEngines)
	}

	// Iterate over the crypto engines of type HashicorpVault
	for _, hashicorpVaultEngine := range config.CryptoEngines.HashicorpVaultKV2Provider {
		newCryptoEngines = addCryptoEngine[HashicorpVaultCryptoEngineConfig](HashicorpVaultProvider, hashicorpVaultEngine, newCryptoEngines)
	}

	// Iterate over the crypto engines of type AWSKMS
	for _, awsKmsEngine := range config.CryptoEngines.AWSKMSProvider {
		newCryptoEngines = addCryptoEngine[AWSCryptoEngine](AWSKMSProvider, awsKmsEngine, newCryptoEngines)
	}

	// Iterate over the crypto engines of type AWSSecretsManager
	for _, awsSecretsManagerEngine := range config.CryptoEngines.AWSSecretsManagerProvider {
		newCryptoEngines = addCryptoEngine[AWSCryptoEngine](AWSSecretsManagerProvider, awsSecretsManagerEngine, newCryptoEngines)
	}

	// Iterate over the crypto engines of type Golang
	for _, golangEngine := range config.CryptoEngines.FilesystemProvider {
		newCryptoEngines = addCryptoEngine[FilesystemEngineConfig](FilesystemProvider, golangEngine, newCryptoEngines)
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

func addCryptoEngine[E any](provider CryptoEngineProvider, config E, newCryptoEngines []CryptoEngine) []CryptoEngine {
	encoded, err := EncodeStruct(config)
	if err != nil {
		panic(err)
	}

	delete(encoded, "id")
	delete(encoded, "metadata")

	var id string
	var metadata map[string]interface{}

	switch t := any(config).(type) {
	case PKCS11EngineConfig:
		id = t.ID
		metadata = t.Metadata
	case HashicorpVaultCryptoEngineConfig:
		id = t.ID
		metadata = t.Metadata
	case AWSCryptoEngine:
		id = t.ID
		metadata = t.Metadata
	case FilesystemEngineConfig:
		id = t.ID
		metadata = t.Metadata
	default:
		panic("Unrecognized config type")
	}

	newCryptoEngines = append(newCryptoEngines, CryptoEngine{
		ID:       id,
		Metadata: metadata,
		Type:     provider,
		Config:   encoded,
	})
	return newCryptoEngines
}
