package config

import "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"

type PostgresPSEConfig struct {
	Hostname string          `mapstructure:"hostname"`
	Port     int             `mapstructure:"port"`
	Username string          `mapstructure:"username"`
	Password config.Password `mapstructure:"password"`
	// MaxOpenConns bounds the connections of each database pool (default 20),
	// so load on one service cannot exhaust PostgreSQL max_connections.
	MaxOpenConns int `mapstructure:"max_open_conns"`
}
