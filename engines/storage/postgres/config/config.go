package config

import (
	"fmt"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
)

type ConnectionTransport string

const (
	DirectConnection ConnectionTransport = "direct"
	RDSDataAPI       ConnectionTransport = "data_api"
)

type PostgresPSEConfig struct {
	Hostname  string              `mapstructure:"hostname"`
	Port      int                 `mapstructure:"port"`
	Username  string              `mapstructure:"username"`
	Password  config.Password     `mapstructure:"password"`
	Transport ConnectionTransport `mapstructure:"transport"`

	RDSResourceARN string `mapstructure:"rds_resource_arn"`
	RDSSecretARN   string `mapstructure:"rds_secret_arn"`
	AWSRegion      string `mapstructure:"aws_region"`
}

func (c PostgresPSEConfig) UsesRDSDataAPI() bool {
	return c.Transport == RDSDataAPI
}

func (c PostgresPSEConfig) Validate() error {
	if !c.UsesRDSDataAPI() {
		return nil
	}

	if c.RDSResourceARN == "" {
		return fmt.Errorf("rds_resource_arn is required when transport is %q", RDSDataAPI)
	}
	if c.RDSSecretARN == "" {
		return fmt.Errorf("rds_secret_arn is required when transport is %q", RDSDataAPI)
	}
	if c.AWSRegion == "" {
		return fmt.Errorf("aws_region is required when transport is %q", RDSDataAPI)
	}

	return nil
}
