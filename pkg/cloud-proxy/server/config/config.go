package config

import "github.com/kelseyhightower/envconfig"

type Config struct {
	Port     string `required:"true" split_words:"true"`
	Protocol string `required:"true" split_words:"true"`
	CertFile string `split_words:"true"`
	KeyFile  string `split_words:"true"`

	MutualTLSEnabled  bool   `split_words:"true"`
	MutualTLSClientCA string `split_words:"true"`

	PostgresPassword           string `required:"true" split_words:"true"`
	PostgresUser               string `required:"true" split_words:"true"`
	PostgresDB                 string `required:"true" split_words:"true"`
	PostgresHostname           string `required:"true" split_words:"true"`
	PostgresPort               string `required:"true" split_words:"true"`
	PostgresMigrationsFilePath string `required:"true" split_words:"true"`

	ConsulProtocol string `required:"true" split_words:"true"`
	ConsulHost     string `required:"true" split_words:"true"`
	ConsulPort     string `required:"true" split_words:"true"`
	ConsulCA       string `required:"true" split_words:"true"`

	AmqpServerHost   string `required:"true" split_words:"true"`
	AmqpServerPort   string `required:"true" split_words:"true"`
	AmqpServerCaCert string `required:"true" split_words:"true"`
	AmqpClientCert   string `required:"true" split_words:"true"`
	AmqpClientKey    string `required:"true" split_words:"true"`

	LamassuCACertFile       string `required:"true" split_words:"true"`
	LamassuCAClientCertFile string `required:"true" split_words:"true"`
	LamassuCAClientKeyFile  string `required:"true" split_words:"true"`
	LamassuCAAddress        string `required:"true" split_words:"true"`
}

func NewConfig(prefix string) (Config, error) {
	var cfg Config
	err := envconfig.Process(prefix, &cfg)
	if err != nil {
		return Config{}, err
	}
	return cfg, nil
}
