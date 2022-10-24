package config

import "github.com/lamassuiot/lamassuiot/pkg/utils/server"

type DeviceManagerConfig struct {
	server.BaseConfiguration

	PostgresPassword string `required:"true" split_words:"true"`
	PostgresUser     string `required:"true" split_words:"true"`
	PostgresDatabase string `required:"true" split_words:"true"`
	PostgresHostname string `required:"true" split_words:"true"`
	PostgresPort     string `required:"true" split_words:"true"`

	LamassuCACertFile string `required:"true" split_words:"true"`
	LamassuCAAddress  string `required:"true" split_words:"true"`

	LamassuDMSManagerCertFile string `required:"true" split_words:"true"`
	LamassuDMSManagerAddress  string `required:"true" split_words:"true"`

	MinimumReenrollDays int `required:"true" split_words:"true"`
}

func NewDeviceManagerConfig() *DeviceManagerConfig {
	return &DeviceManagerConfig{}
}

func (c *DeviceManagerConfig) GetBaseConfiguration() *server.BaseConfiguration {
	return &c.BaseConfiguration
}

func (c *DeviceManagerConfig) GetConfiguration() interface{} {
	return c
}
