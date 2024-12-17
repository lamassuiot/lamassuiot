package config

import "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"

type PostgresPSEConfig struct {
	Hostname      string          `mapstructure:"hostname"`
	Port          int             `mapstructure:"port"`
	Username      string          `mapstructure:"username"`
	Password      config.Password `mapstructure:"password"`
	MigrationsDir string          `mapstructure:"migrations_directory"`
}
