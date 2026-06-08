package config

import cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"

type AuthzClient struct {
	cconfig.HTTPClient `mapstructure:",squash"`
}
