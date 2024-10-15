package config

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
	GolangProvider            []GolangEngineConfig               `mapstructure:"golang"`
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

type GolangEngineConfig struct {
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

func MigrateCryptoEnginesToV2Config(config *CAConfig) *CAConfig {

	// Migrate CryptoEngines to V2
	// Process each crypto engine config an convert into the new format CryptoEngine
	// This is done to ensure that the config is backward compatible with the previous version
	// of the config

	if config.CryptoEngines.CryptoEngines != nil {
		return config
	}

	// Create a new slice to hold the new crypto engines
	newCryptoEngines := make([]CryptoEngine, 0)
	// Iterate over the crypto engines of type PKCS11
	for _, pkcs11Engine := range config.CryptoEngines.PKCS11Provider {
		encoded, err := EncodeStruct(pkcs11Engine)
		if err != nil {
			panic(err)
		}
		newCryptoEngines = append(newCryptoEngines, CryptoEngine{
			ID:       pkcs11Engine.ID,
			Metadata: pkcs11Engine.Metadata,
			Type:     PKCS11Provider,
			Config:   encoded,
		})
	}

	// Iterate over the crypto engines of type HashicorpVault
	for _, hashicorpVaultEngine := range config.CryptoEngines.HashicorpVaultKV2Provider {
		encoded, err := EncodeStruct(hashicorpVaultEngine)
		if err != nil {
			panic(err)
		}
		newCryptoEngines = append(newCryptoEngines, CryptoEngine{
			ID:       hashicorpVaultEngine.ID,
			Metadata: hashicorpVaultEngine.Metadata,
			Type:     HashicorpVaultProvider,
			Config:   encoded,
		})
	}

	// Iterate over the crypto engines of type AWSKMS
	for _, awsKmsEngine := range config.CryptoEngines.AWSKMSProvider {
		encoded, err := EncodeStruct(awsKmsEngine)
		if err != nil {
			panic(err)
		}
		newCryptoEngines = append(newCryptoEngines, CryptoEngine{
			ID:       awsKmsEngine.ID,
			Metadata: awsKmsEngine.Metadata,
			Type:     AWSKMSProvider,
			Config:   encoded,
		})
	}

	// Iterate over the crypto engines of type AWSSecretsManager
	for _, awsSecretsManagerEngine := range config.CryptoEngines.AWSSecretsManagerProvider {
		encoded, err := EncodeStruct(awsSecretsManagerEngine)
		if err != nil {
			panic(err)
		}

		newCryptoEngines = append(newCryptoEngines, CryptoEngine{
			ID:       awsSecretsManagerEngine.ID,
			Metadata: awsSecretsManagerEngine.Metadata,
			Type:     AWSSecretsManagerProvider,
			Config:   encoded,
		})
	}

	// Iterate over the crypto engines of type Golang
	for _, golangEngine := range config.CryptoEngines.GolangProvider {
		encoded, err := EncodeStruct(golangEngine)
		if err != nil {
			panic(err)
		}

		newCryptoEngines = append(newCryptoEngines, CryptoEngine{
			ID:       golangEngine.ID,
			Metadata: golangEngine.Metadata,
			Type:     GolangProvider,
			Config:   encoded,
		})
	}

	config.CryptoEngines.CryptoEngines = newCryptoEngines

	return config
}
