package config

type VAconfig struct {
	BaseConfig `mapstructure:",squash"`

	CAClient CAClient `mapstructure:"ca_client"`
}

type CAClient struct {
	HTTPClient `mapstructure:",squash"`
}
