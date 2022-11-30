package config

import "github.com/lamassuiot/lamassuiot/pkg/utils/server"

type DMSManagerConfig struct {
	server.BaseConfiguration

	PostgresPassword string `required:"true" split_words:"true"`
	PostgresUser     string `required:"true" split_words:"true"`
	PostgresDatabase string `required:"true" split_words:"true"`
	PostgresHostname string `required:"true" split_words:"true"`
	PostgresPort     string `required:"true" split_words:"true"`

	LamassuCAAddress  string `required:"true" split_words:"true"`
	LamassuCACertFile string `split_words:"true"`
}

func NewDMSManagerConfig() *DMSManagerConfig {
	return &DMSManagerConfig{}
}

func (c *DMSManagerConfig) GetBaseConfiguration() *server.BaseConfiguration {
	return &c.BaseConfiguration
}

func (c *DMSManagerConfig) GetConfiguration() interface{} {
	return c
}
