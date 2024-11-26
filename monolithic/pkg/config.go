package pkg

import (
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	laws "github.com/lamassuiot/lamassuiot/shared/aws/v3"
)

type LamassuMonolithicAssembleMode string

const (
	//all Lamassu service but the proxy server are deployed in memory. If services interact between them,
	//they do so by using each other's Business Logic (aka Service).
	InMemory LamassuMonolithicAssembleMode = "IN_MEMORY"
	//each Lamassu service is deployed as separate HTTP servers. If services interact between them, HTTP clients (SDKs) are used
	Http LamassuMonolithicAssembleMode = "HTTP"
)

type MonolithicConfig struct {
	Logs               cconfig.Logging                `mapstructure:"logs"`
	PublisherEventBus  cconfig.EventBusEngine         `mapstructure:"publisher_event_bus"`
	SubscriberEventBus cconfig.EventBusEngine         `mapstructure:"subscriber_event_bus"`
	Storage            cconfig.PluggableStorageEngine `mapstructure:"storage"`
	CryptoEngines      []cconfig.CryptoEngineConfig   `mapstructure:"crypto_engines"`
	CryptoMonitoring   cconfig.MonitoringJob          `mapstructure:"crypto_monitoring"`
	Domain             string                         `mapstructure:"domain"`
	AssemblyMode       LamassuMonolithicAssembleMode  `mapstructure:"assembly_mode"`
	GatewayPort        int                            `mapstructure:"gateway_port"`
	AWSIoTManager      MonolithicAWSIoTManagerConfig  `mapstructure:"aws_iot_manager"`
}

type MonolithicAWSIoTManagerConfig struct {
	Enabled      bool              `mapstructure:"enabled"`
	ConnectorID  string            `mapstructure:"connector_id"`
	AWSSDKConfig laws.AWSSDKConfig `mapstructure:"aws_config"`
}
