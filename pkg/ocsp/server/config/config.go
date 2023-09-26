package config

import (
	"github.com/lamassuiot/lamassuiot/pkg/utils/server"
)

type OCSPConfig struct {
	server.BaseConfiguration

	SignerKey  string `required:"true" split_words:"true"`
	SignerCert string `required:"true" split_words:"true"`

	LamassuCAAddress  string `required:"true" split_words:"true"`
	LamassuCACertFile string `split_words:"true"`
}

func NewOCSPConfig() *OCSPConfig {
	return &OCSPConfig{}
}

func (c *OCSPConfig) GetBaseConfiguration() *server.BaseConfiguration {
	return &c.BaseConfiguration
}

func (c *OCSPConfig) GetConfiguration() interface{} {
	return c
}
