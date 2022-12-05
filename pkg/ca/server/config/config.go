package config

import (
	"github.com/lamassuiot/lamassuiot/pkg/utils/server"
)

type CAConfig struct {
	server.BaseConfiguration

	OcspUrl           string `required:"true" split_words:"true"`
	AboutToExpireDays int    `required:"true" split_words:"true"`

	PostgresDatabase     string `required:"true" split_words:"true"`
	PostgresUsernamename string `required:"true" split_words:"true"`
	PostgresPassword     string `required:"true" split_words:"true"`
	PostgresHostname     string `required:"true" split_words:"true"`
	PostgresPort         string `required:"true" split_words:"true"`

	Engine string `required:"true" split_words:"true"`

	GopemData string `split_words:"true"`

	VaultUnsealKeysFile string `split_words:"true"`
	VaultAddress        string `split_words:"true"`
	VaultRoleID         string `split_words:"true"`
	VaultSecretID       string `split_words:"true"`
	VaultCA             string `split_words:"true"`
	VaultPkiCaPath      string `split_words:"true"`
}

func NewCAConfig() *CAConfig {
	return &CAConfig{}
}

func (c *CAConfig) GetBaseConfiguration() *server.BaseConfiguration {
	return &c.BaseConfiguration
}

func (c *CAConfig) GetConfiguration() interface{} {
	return c
}
