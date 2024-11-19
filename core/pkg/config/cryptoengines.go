package config

type CryptoEngine[E any] struct {
	ID       string                 `mapstructure:"id"`
	Metadata map[string]interface{} `mapstructure:"metadata"`
	Type     CryptoEngineProvider   `mapstructure:"type"`
	Config   E                      `mapstructure:",remain"`
}

type CryptoEngineProvider string

const (
	HashicorpVaultProvider    CryptoEngineProvider = "hashicorp_vault"
	AWSKMSProvider            CryptoEngineProvider = "aws_kms"
	AWSSecretsManagerProvider CryptoEngineProvider = "aws_secrets_manager"
	FilesystemProvider        CryptoEngineProvider = "filesystem"
	PKCS11Provider            CryptoEngineProvider = "pkcs11"
)
