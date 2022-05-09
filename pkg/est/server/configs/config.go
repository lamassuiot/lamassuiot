package configs

import "github.com/kelseyhightower/envconfig"

type Config struct {
	Port string `required:"true" split_words:"true"`

	CertFile string `split_words:"true"`
	KeyFile  string `split_words:"true"`

	LamassuCAServerAddr string `split_words:"true"`
	LamassuCACertFile   string `split_words:"true"`
}

func NewConfig(prefix string) (Config, error) {
	var cfg Config
	err := envconfig.Process(prefix, &cfg)
	if err != nil {
		return Config{}, err
	}
	return cfg, nil
}
