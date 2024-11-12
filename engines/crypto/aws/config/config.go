package config

import (
	cconfig "github.com/lamassuiot/lamassuiot/v3/core/pkg/config"
)

type AWSCryptoEngine struct {
	cconfig.AWSSDKConfig `mapstructure:",squash"`
	ID                   string                 `mapstructure:"id"`
	Metadata             map[string]interface{} `mapstructure:"metadata"`
}
