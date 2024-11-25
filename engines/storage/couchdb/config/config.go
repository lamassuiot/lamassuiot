package config

import "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"

type CouchDBPSEConfig struct {
	config.HTTPConnection `mapstructure:",squash"`
	Username              string          `mapstructure:"username"`
	Password              config.Password `mapstructure:"password"`
}
