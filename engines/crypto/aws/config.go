package aws

import (
	laws "github.com/lamassuiot/lamassuiot/v4/shared/aws"
)

type AWSCryptoEngine struct {
	laws.AWSSDKConfig `mapstructure:",squash"`
	ID                string         `mapstructure:"id"`
	Metadata          map[string]any `mapstructure:"metadata"`
}
