package config

import (
	"github.com/lamassuiot/lamassuiot/pkg/utils/server"
)

type CloudProxyConfig struct {
	server.BaseConfiguration

	PostgresPassword string `required:"true" split_words:"true"`
	PostgresUser     string `required:"true" split_words:"true"`
	PostgresDatabase string `required:"true" split_words:"true"`
	PostgresHostname string `required:"true" split_words:"true"`
	PostgresPort     string `required:"true" split_words:"true"`

	ConsulProtocol string `required:"true" split_words:"true"`
	ConsulHost     string `required:"true" split_words:"true"`
	ConsulPort     string `required:"true" split_words:"true"`
	ConsulCA       string `required:"true" split_words:"true"`

	LamassuCAAddress  string `required:"true" split_words:"true"`
	LamassuCACertFile string `split_words:"true"`

	LamassuConnectorsMutualTLS bool   `required:"true" split_words:"true"`
	LamassuConnectorsCertFile  string `split_words:"true"`
}

func NewCloudProxyConfig() *CloudProxyConfig {
	return &CloudProxyConfig{}
}

func (c *CloudProxyConfig) GetBaseConfiguration() *server.BaseConfiguration {
	return &c.BaseConfiguration
}

func (c *CloudProxyConfig) GetConfiguration() interface{} {
	return c
}
