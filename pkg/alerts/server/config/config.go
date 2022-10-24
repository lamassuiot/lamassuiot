package config

import (
	"github.com/lamassuiot/lamassuiot/pkg/utils/server"
)

type MailConfig struct {
	server.BaseConfiguration

	PostgresDatabase string `required:"true" split_words:"true"`
	PostgresUser     string `required:"true" split_words:"true"`
	PostgresPassword string `required:"true" split_words:"true"`
	PostgresHostname string `required:"true" split_words:"true"`
	PostgresPort     string `required:"true" split_words:"true"`

	SMTPHost      string `required:"true" split_words:"true"`
	SMTPPort      int    `required:"true" split_words:"true"`
	SMTPUsername  string `required:"true" split_words:"true"`
	SMTPPassword  string `required:"true" split_words:"true"`
	SMTPFrom      string `required:"true" split_words:"true"`
	SMTPEnableSSL bool   `required:"true" split_words:"true"`
	SMTPInsecure  bool   `required:"true" split_words:"true"`

	TemplateHTML string `required:"true" split_words:"true"`
	TemplateJSON string `required:"true" split_words:"true"`
}

func NewMailConfig() *MailConfig {
	return &MailConfig{}
}

func (c *MailConfig) GetBaseConfiguration() *server.BaseConfiguration {
	return &c.BaseConfiguration
}

func (c *MailConfig) GetConfiguration() interface{} {
	return c
}
