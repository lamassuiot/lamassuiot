package config

import "github.com/kelseyhightower/envconfig"

type Config struct {
	Port string `required:"true" split_words:"true"`
	// Protocol string `required:"true" split_words:"true"`
	// CertFile string `split_words:"true"`
	// KeyFile  string `split_words:"true"`

	// MutualTLSEnabled  bool   `split_words:"true"`
	// MutualTLSClientCA string `split_words:"true"`

	AmqpServerHost   string `required:"true" split_words:"true"`
	AmqpServerPort   string `required:"true" split_words:"true"`
	AmqpServerCaCert string `required:"true" split_words:"true"`
	AmqpClientCert   string `required:"true" split_words:"true"`
	AmqpClientKey    string `required:"true" split_words:"true"`

	EmailFrom       string `required:"true" split_words:"true"`
	EmailPassword   string `required:"true" split_words:"true"`
	EmailSMTPServer string `required:"true" split_words:"true"`

	TemplateData string `required:"true" split_words:"true"`

	PostgresDatabase string `required:"true" split_words:"true"`
	PostgresUser     string `required:"true" split_words:"true"`
	PostgresPassword string `required:"true" split_words:"true"`
	PostgresHostname string `required:"true" split_words:"true"`
	PostgresPort     string `required:"true" split_words:"true"`
}

func NewConfig(prefix string) (Config, error) {
	var cfg Config
	err := envconfig.Process(prefix, &cfg)
	if err != nil {
		return Config{}, err
	}
	return cfg, nil
}
