package aws

import cconfig "github.com/lamassuiot/lamassuiot/v3/core/pkg/config"

type AWSAuthenticationMethod string

const (
	Static     AWSAuthenticationMethod = "static"
	Default    AWSAuthenticationMethod = "default"
	AssumeRole AWSAuthenticationMethod = "role"
)

type AWSSDKConfig struct {
	AWSAuthenticationMethod AWSAuthenticationMethod `mapstructure:"auth_method"`
	EndpointURL             string                  `mapstructure:"endpoint_url"`
	AccessKeyID             string                  `mapstructure:"access_key_id"`
	SecretAccessKey         cconfig.Password        `mapstructure:"secret_access_key"`
	SessionToken            cconfig.Password        `mapstructure:"session_token"`
	Region                  string                  `mapstructure:"region"`
	RoleARN                 string                  `mapstructure:"role_arn"`
}
