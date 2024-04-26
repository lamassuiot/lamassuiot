package config

type VAconfig struct {
	Logs   BaseConfigLogging `mapstructure:"logs"`
	Server HttpServer        `mapstructure:"server"`

	CAClient CAClient `mapstructure:"ca_client"`
}

type CAClient struct {
	HTTPClient `mapstructure:",squash"`
}
