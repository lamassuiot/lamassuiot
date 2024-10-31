package config

import (
	"github.com/lamassuiot/lamassuiot/v2/core/pkg/config"
)

type AWSCryptoEngine struct {
	AWSSDKConfig `mapstructure:",squash"`
	ID           string                 `mapstructure:"id"`
	Metadata     map[string]interface{} `mapstructure:"metadata"`
}

type AWSSDKConfig struct {
	AWSAuthenticationMethod config.AWSAuthenticationMethod `mapstructure:"auth_method"`
	EndpointURL             string                         `mapstructure:"endpoint_url"`
	AccessKeyID             string                         `mapstructure:"access_key_id"`
	SecretAccessKey         config.Password                `mapstructure:"secret_access_key"`
	SessionToken            config.Password                `mapstructure:"session_token"`
	Region                  string                         `mapstructure:"region"`
	RoleARN                 string                         `mapstructure:"role_arn"`
}
