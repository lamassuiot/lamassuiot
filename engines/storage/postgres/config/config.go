package config

import "github.com/lamassuiot/lamassuiot/v4/core/pkg/config"

type PostgresTransport string

const (
	PostgresTransportDirect     PostgresTransport = "direct"
	PostgresTransportRDSDataAPI PostgresTransport = "rds_data_api"
)

// PostgresPSEConfig configures PostgreSQL storage. An empty transport retains the
// direct TCP connection. To opt in to RDS Data API, set transport to "rds_data_api"
// and populate the rds_data_api block; AWS credentials use the SDK default chain.
type PostgresPSEConfig struct {
	// Transport selects direct TCP PostgreSQL (the zero-value default) or the RDS Data API.
	Transport  PostgresTransport `mapstructure:"transport"`
	Hostname   string            `mapstructure:"hostname"`
	Port       int               `mapstructure:"port"`
	Username   string            `mapstructure:"username"`
	Password   config.Password   `mapstructure:"password"`
	RDSDataAPI RDSDataAPIConfig  `mapstructure:"rds_data_api"`
}

// RDSDataAPIConfig contains the RDS Data API connection parameters.
type RDSDataAPIConfig struct {
	ResourceARN string `mapstructure:"resource_arn"`
	SecretARN   string `mapstructure:"secret_arn"`
	Database    string `mapstructure:"database"`
	AWSRegion   string `mapstructure:"aws_region"`
}
