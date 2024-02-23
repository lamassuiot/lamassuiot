package awsengine

import "github.com/lamassuiot/lamassuiot/v2/core/config"

type AWSCryptoEngineConfig struct {
	config.AWSSDKConfig `mapstructure:",squash"`
	ID                  string                 `mapstructure:"id"`
	Metadata            map[string]interface{} `mapstructure:"metadata"`
}
