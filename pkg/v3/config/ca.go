package config

type CAConfig struct {
	BaseConfig `mapstructure:",squash"`
	Storage    PluggableStorageEngine `mapstructure:"storage"`

	CryptoEngines struct {
		DefaultEngine             string                             `mapstructure:"default_id"`
		PKCS11Provider            []PKCS11EngineConfig               `mapstructure:"pkcs11"`
		HashicorpVaultKV2Provider []HashicorpVaultCryptoEngineConfig `mapstructure:"hashicorp_vault"`
		AWSKMSProvider            []AWSSDKConfig                     `mapstructure:"aws_kms"`
		AWSSecretsManagerProvider []AWSSDKConfig                     `mapstructure:"aws_secrets_manager"`
		GolangProvider            []GolangEngineConfig               `mapstructure:"golang"`
	} `mapstructure:"crypto_engines"`

	CryptoMonitoring `mapstructure:"crypto_monitoring"`
	OCSPServerURL    string `mapstructure:"ocsp_server_url"`
}

type HashicorpVaultCryptoEngineConfig struct {
	HashicorpVaultSDK
	ID       string                 `mapstructure:"id"`
	Metadata map[string]interface{} `mapstructure:"metadata"`
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

type PKCS11EngineConfig struct {
	ID                 string                   `mapstructure:"id"`
	Metadata           map[string]interface{}   `mapstructure:"metadata"`
	TokenLabel         string                   `mapstructure:"token"`
	TokenPin           Password                 `mapstructure:"pin"`
	ModulePath         string                   `mapstructure:"module_path"`
	ModuleExtraOptions PKCS11ModuleExtraOptions `mapstructure:"module_extra_options"`
}

type PKCS11ModuleExtraOptions struct {
	Env map[string]string `mapstructure:"env"`
}

type AWSSDKConfig struct {
	ID              string                 `mapstructure:"id"`
	Metadata        map[string]interface{} `mapstructure:"metadata"`
	AccessKeyID     string                 `mapstructure:"access_key_id"`
	SecretAccessKey Password               `mapstructure:"secret_access_key"`
	Region          string                 `mapstructure:"region"`
}

type CryptoMonitoring struct {
	Enabled             bool   `mapstructure:"enabled"`
	Frequency           string `mapstructure:"frequency"`
	StatusMachineDeltas struct {
		NearExpiration     string `mapstructure:"near_expiration"`
		CriticalExpiration string `mapstructure:"critical_expiration"`
	} `mapstructure:"status_machine_deltas"`
	AutomaticCARotation struct {
		Enabled      bool   `mapstructure:"enabled"`
		RenewalDelta string `mapstructure:"renewal_delta"`
	} `mapstructure:"automatic_ca_rotation"`
}
