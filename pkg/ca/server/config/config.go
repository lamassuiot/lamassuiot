package config

import "github.com/kelseyhightower/envconfig"

type Config struct {
	Port string `required:"true" split_words:"true"`

	OcspUrl string `required:"true" split_words:"true"`

	Protocol string `required:"true" split_words:"true"`
	CertFile string `split_words:"true"`
	KeyFile  string `split_words:"true"`

	MutualTLSEnabled  bool   `split_words:"true"`
	MutualTLSClientCA string `split_words:"true"`

	VaultUnsealKeysFile string `required:"true" split_words:"true"`

	VaultAddress  string `required:"true" split_words:"true"`
	VaultRoleID   string `required:"true" split_words:"true"`
	VaultSecretID string `required:"true" split_words:"true"`
	VaultCA       string `split_words:"true"`

	VaultPkiCaPath string `required:"true" split_words:"true"`

	PostgresUser               string `required:"true" split_words:"true"`
	PostgresCaDB               string `required:"true" split_words:"true"`
	PostgresPassword           string `required:"true" split_words:"true"`
	PostgresHostname           string `required:"true" split_words:"true"`
	PostgresPort               string `required:"true" split_words:"true"`
	PostgresMigrationsFilePath string `required:"true" split_words:"true"`

	DebugMode string `required:"true" split_words:"true"`

	AmqpIP               string `required:"true" split_words:"true"`
	AmqpPort             string `required:"true" split_words:"true"`
	AmqpServerCACertFile string `required:"true" split_words:"true"`

	OpenapiEnableSecuritySchema     bool   `required:"true" split_words:"true"`
	OpenapiSecurityOidcWellKnownUrl string `split_words:"true"`
}

func NewConfig(prefix string) (Config, error) {
	var cfg Config
	err := envconfig.Process(prefix, &cfg)
	if err != nil {
		return Config{}, err
	}
	return cfg, nil
}
