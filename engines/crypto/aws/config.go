package aws

import (
	laws "github.com/lamassuiot/lamassuiot/v3/aws"
)

type AWSCryptoEngine struct {
	laws.AWSSDKConfig `mapstructure:",squash"`
	ID                string                 `mapstructure:"id"`
	Metadata          map[string]interface{} `mapstructure:"metadata"`
}
