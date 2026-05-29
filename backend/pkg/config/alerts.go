package config

import (
	"time"

	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
)

type AlertsConfig struct {
	OtelConfig            cconfig.OTELConfig             `mapstructure:"otel"`
	Logs                  cconfig.Logging                `mapstructure:"logs"`
	Server                cconfig.HttpServer             `mapstructure:"server"`
	SubscriberEventBus    cconfig.EventBusEngine         `mapstructure:"subscriber_event_bus"`
	SubscriberDLQEventBus cconfig.EventBusEngine         `mapstructure:"subscriber_dlq_event_bus"`
	Storage               cconfig.PluggableStorageEngine `mapstructure:"storage"`
	SMTPConfig            SMTPServer                     `mapstructure:"smtp_server"`
	EventStorage          EventStorageConfig             `mapstructure:"event_storage"`
}

type SMTPServer struct {
	From     string `mapstructure:"from"`
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
	SSL      bool   `mapstructure:"ssl"`
	Insecure bool   `mapstructure:"insecure"`
}

type EventStorageConfig struct {
	// Seed default written to DB on first run; subsequent restarts do not overwrite the DB value.
	DefaultAuditEventTTL time.Duration `mapstructure:"default_audit_event_ttl"`
	CleanupInterval      time.Duration `mapstructure:"cleanup_interval"`
}
