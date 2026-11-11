// Package config contains the configuration for the Oracle storage engine.
package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	coreconfig "github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
)

// Config describes an Oracle connection and its database/sql pool.
// ConnectString may contain an Oracle Easy Connect or TCPS connection string.
type Config struct {
	ConnectString   string              `mapstructure:"connect_string"`
	Username        string              `mapstructure:"username"`
	Password        coreconfig.Password `mapstructure:"password"`
	MaxOpenConns    int                 `mapstructure:"max_open_conns"`
	MaxIdleConns    int                 `mapstructure:"max_idle_conns"`
	ConnMaxLifetime time.Duration       `mapstructure:"conn_max_lifetime"`
}

// Decode accepts the duration strings used in configuration files.
func Decode(source map[string]any) (Config, error) {
	var cfg Config
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:     &cfg,
		TagName:    "mapstructure",
		DecodeHook: mapstructure.StringToTimeDurationHookFunc(),
	})
	if err != nil {
		return Config{}, fmt.Errorf("create oracle config decoder: %w", err)
	}
	if err := decoder.Decode(source); err != nil {
		return Config{}, fmt.Errorf("decode oracle config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate rejects invalid pool settings before a connection is opened.
// Zero pool values retain database/sql's defaults.
func (c Config) Validate() error {
	if strings.TrimSpace(c.ConnectString) == "" {
		return fmt.Errorf("oracle connect_string is required")
	}
	if strings.TrimSpace(c.Username) == "" {
		return fmt.Errorf("oracle username is required")
	}
	if c.MaxOpenConns < 0 || c.MaxIdleConns < 0 || c.ConnMaxLifetime < 0 {
		return fmt.Errorf("oracle pool settings cannot be negative")
	}
	if c.MaxOpenConns > 0 && c.MaxIdleConns > c.MaxOpenConns {
		return fmt.Errorf("oracle max_idle_conns cannot exceed max_open_conns")
	}
	return nil
}
