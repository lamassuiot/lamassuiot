package config

type AlertsConfig struct {
	Logs               BaseConfigLogging      `mapstructure:"logs"`
	Server             HttpServer             `mapstructure:"server"`
	SubscriberEventBus EventBusEngine         `mapstructure:"subscriber_event_bus"`
	Storage            PluggableStorageEngine `mapstructure:"storage"`
	SMTPConfig         SMTPServer             `mapstructure:"smtp_server"`
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
