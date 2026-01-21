package config

import cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"

type AlertsConfig struct {
	OpenAPI               cconfig.OpenAPIConfig          `mapstructure:"openapi"`
	Logs                  cconfig.Logging                `mapstructure:"logs"`
	Server                cconfig.HttpServer             `mapstructure:"server"`
	SubscriberEventBus    cconfig.EventBusEngine         `mapstructure:"subscriber_event_bus"`
	SubscriberDLQEventBus cconfig.EventBusEngine         `mapstructure:"subscriber_dlq_event_bus"`
	Storage               cconfig.PluggableStorageEngine `mapstructure:"storage"`
	SMTPConfig            SMTPServer                     `mapstructure:"smtp_server"`
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
