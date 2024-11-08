package config

import cconfig "github.com/lamassuiot/lamassuiot/v2/core/pkg/config"

type AlertsConfig struct {
	Logs               cconfig.Logging                `mapstructure:"logs"`
	Server             cconfig.HttpServer             `mapstructure:"server"`
	SubscriberEventBus cconfig.EventBusEngine         `mapstructure:"subscriber_event_bus"`
	Storage            cconfig.PluggableStorageEngine `mapstructure:"storage"`
	SMTPConfig         SMTPServer                     `mapstructure:"smtp_server"`
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
