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
	LogLevel       LogLevel             `mapstructure:"log_level"`
	DefaultEngine  string               `mapstructure:"default_id"`
	PKCS11Provider []PKCS11EngineConfig `mapstructure:"pkcs11"`
	AWSKMSProvider []AWSCryptoEngine    `mapstructure:"aws_kms"`

	//Go-based engines
	GolangHashicorpVaultKV2Provider []HashicorpVaultCryptoEngineConfig `mapstructure:"hashicorp_vault"`
	GolangAWSSecretsManagerProvider []AWSCryptoEngine                  `mapstructure:"aws_secrets_manager"`
	GolangFilesystemProvider        []GolangFilesystemEngineConfig     `mapstructure:"filesystem"`
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

type GolangFilesystemEngineConfig struct {
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
	Region                  string                  `mapstructure:"region"`
	RoleARN                 string                  `mapstructure:"role_arn"`
}

type CryptoMonitoring struct {
	Enabled   bool   `mapstructure:"enabled"`
	Frequency string `mapstructure:"frequency"`
}
