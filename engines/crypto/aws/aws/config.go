package aws

import (
	laws "github.com/lamassuiot/lamassuiot/shared/aws/v3"
)

type AWSCryptoEngine struct {
	laws.AWSSDKConfig `mapstructure:",squash"`
	ID                string                 `mapstructure:"id"`
	Metadata          map[string]interface{} `mapstructure:"metadata"`
}
