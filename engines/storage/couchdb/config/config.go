package config

import "github.com/lamassuiot/lamassuiot/v3/core/pkg/config"

type CouchDBPSEConfig struct {
	config.HTTPConnection `mapstructure:",squash"`
	Username              string          `mapstructure:"username"`
	Password              config.Password `mapstructure:"password"`
}
