package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
)

// Pool defaults applied when a setting is omitted (zero). They match the
// limits Authz sets on its PostgreSQL connections.
const (
	DefaultOracleMaxOpenConns    = 25
	DefaultOracleMaxIdleConns    = 5
	DefaultOracleConnMaxLifetime = 5 * time.Minute
)

// OracleDBConfig configures an Oracle database connection used by Authz.
type OracleDBConfig struct {
	ConnectString   string        `mapstructure:"connect_string"`
	Username        string        `mapstructure:"username"`
	Password        string        `mapstructure:"password"`
	MaxOpenConns    int           `mapstructure:"max_open_conns"`
	MaxIdleConns    int           `mapstructure:"max_idle_conns"`
	ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime"`
}

// DecodeOracleDBConfig decodes and validates Authz's Oracle connection
// settings without depending on the Oracle storage engine's config package.
func DecodeOracleDBConfig(source map[string]any) (OracleDBConfig, error) {
	var cfg OracleDBConfig
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:     &cfg,
		TagName:    "mapstructure",
		DecodeHook: mapstructure.StringToTimeDurationHookFunc(),
	})
	if err != nil {
		return OracleDBConfig{}, fmt.Errorf("create Oracle Authz config decoder: %w", err)
	}
	if err := decoder.Decode(source); err != nil {
		return OracleDBConfig{}, fmt.Errorf("decode Oracle Authz config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return OracleDBConfig{}, err
	}
	cfg.applyPoolDefaults()
	return cfg, nil
}

// applyPoolDefaults fills omitted pool settings so an Oracle connection is
// never left with an unbounded pool. An explicit max_open_conns below the
// idle default also caps the default idle count.
func (c *OracleDBConfig) applyPoolDefaults() {
	if c.MaxOpenConns == 0 {
		c.MaxOpenConns = DefaultOracleMaxOpenConns
	}
	if c.MaxIdleConns == 0 {
		c.MaxIdleConns = min(DefaultOracleMaxIdleConns, c.MaxOpenConns)
	}
	if c.ConnMaxLifetime == 0 {
		c.ConnMaxLifetime = DefaultOracleConnMaxLifetime
	}
}

func (c OracleDBConfig) Validate() error {
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
