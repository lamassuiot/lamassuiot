package config

type VAconfig struct {
	BaseConfig `mapstructure:",squash"`

	CAClient struct {
		HTTPClient `mapstructure:",squash"`
	} `mapstructure:"ca_client"`
}
