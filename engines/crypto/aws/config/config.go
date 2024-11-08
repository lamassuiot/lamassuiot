package config

import (
	cconfig "github.com/lamassuiot/lamassuiot/v2/core/pkg/config"
)

type AWSCryptoEngine struct {
	cconfig.AWSSDKConfig `mapstructure:",squash"`
	ID                   string                 `mapstructure:"id"`
	Metadata             map[string]interface{} `mapstructure:"metadata"`
}
