package config

import cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"

// AuthzConfig is the top-level configuration for the authz service.
// Loaded via cconfig.LoadConfig[AuthzConfig](nil) — reads from LAMASSU_CONFIG_FILE env var
// or falls back to /etc/lamassuiot/config.yml.
type AuthzConfig struct {
	OtelConfig         cconfig.OTELConfig             `mapstructure:"otel"`
	Logs               cconfig.Logging                `mapstructure:"logs"`
	Server             cconfig.HttpServer             `mapstructure:"server"`
	PublisherEventBus  cconfig.EventBusEngine         `mapstructure:"publisher_event_bus"`
	SubscriberEventBus cconfig.EventBusEngine         `mapstructure:"subscriber_event_bus"`
	Schemas            map[string]string              `mapstructure:"schemas"`
	// Credentials holds per-schema engine Postgres connections (provider must be "postgres").
	Credentials map[string]cconfig.PluggableStorageEngine `mapstructure:"credentials"`
	// AuthzDB is the Postgres database for principals, grants, and policies.
	AuthzDB    cconfig.PluggableStorageEngine `mapstructure:"authz_db"`
	PreloadDir string                         `mapstructure:"preload_dir"`
}
