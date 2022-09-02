package config

import (
	"github.com/lamassuiot/lamassuiot/pkg/utils/server"
)

type MailConfig struct {
	server.BaseConfiguration
	/*EmailFrom       string `required:"true" split_words:"true"`
	EmailPassword   string `required:"true" split_words:"true"`
	EmailSMTPServer string `required:"true" split_words:"true"`

	TemplateData string `required:"true" split_words:"true"`*/

	PostgresDatabase string `required:"true" split_words:"true"`
	PostgresUser     string `required:"true" split_words:"true"`
	PostgresPassword string `required:"true" split_words:"true"`
	PostgresHostname string `required:"true" split_words:"true"`
	PostgresPort     string `required:"true" split_words:"true"`

	EmailFrom string `required:"true" split_words:"true"`
	EnableSSL string `required:"true" split_words:"true"`
	Insecure  string `required:"true" split_words:"true"`

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
