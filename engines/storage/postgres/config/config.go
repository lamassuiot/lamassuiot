package config

import "github.com/lamassuiot/lamassuiot/v3/core/pkg/config"

type PostgresPSEConfig struct {
	Hostname string          `mapstructure:"hostname"`
	Port     int             `mapstructure:"port"`
	Username string          `mapstructure:"username"`
	Password config.Password `mapstructure:"password"`
}
