package config

type CAConfig struct {
	Logs              BaseConfigLogging      `mapstructure:"logs"`
	Server            HttpServer             `mapstructure:"server"`
	PublisherEventBus EventBusEngine         `mapstructure:"publisher_event_bus"`
	Storage           PluggableStorageEngine `mapstructure:"storage"`
	CryptoMonitoring  CryptoMonitoring       `mapstructure:"crypto_monitoring"`
	VAServerDomain    string                 `mapstructure:"va_server_domain"`

	KMSClient struct {
		HTTPClient `mapstructure:",squash"`
	} `mapstructure:"kms_client"`
}

type CryptoMonitoring struct {
	Enabled   bool   `mapstructure:"enabled"`
	Frequency string `mapstructure:"frequency"`
}
