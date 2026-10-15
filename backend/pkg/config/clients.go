package config

import cconfig "github.com/lamassuiot/lamassuiot/v4/core/pkg/config"

type CAClient struct {
	cconfig.HTTPClient `mapstructure:",squash"`
}

type KMSClient struct {
	cconfig.HTTPClient `mapstructure:",squash"`
}

type AuthzClient struct {
	cconfig.HTTPClient `mapstructure:",squash"`
}
