package config

type CryptoEngine struct {
	ID       string                 `mapstructure:"id"`
	Metadata map[string]interface{} `mapstructure:"metadata"`
	Type     CryptoEngineProvider   `mapstructure:"type"`
	Config   map[string]interface{} `mapstructure:",remain"`
}

type CryptoEngineProvider string

const (
	HashicorpVaultProvider    CryptoEngineProvider = "hashicorp_vault"
	AWSKMSProvider            CryptoEngineProvider = "aws_kms"
	AWSSecretsManagerProvider CryptoEngineProvider = "aws_secrets_manager"
	FilesystemProvider        CryptoEngineProvider = "filesystem"
	PKCS11Provider            CryptoEngineProvider = "pkcs11"
)

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

type FilesystemEngineConfig struct {
	ID               string                 `mapstructure:"id"`
	Metadata         map[string]interface{} `mapstructure:"metadata"`
	StorageDirectory string                 `mapstructure:"storage_directory"`
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
