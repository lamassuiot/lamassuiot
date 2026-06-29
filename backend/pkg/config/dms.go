package config

import (
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
)

type DMSWFXConfig struct {
	Enabled            bool                `mapstructure:"enabled"`
	Workflow           string              `mapstructure:"workflow"`
	Timeout            models.TimeDuration `mapstructure:"timeout"`
	Tags               []string            `mapstructure:"tags"`
	cconfig.HTTPClient `mapstructure:",squash"`
}

type DMSconfig struct {
	OtelConfig        cconfig.OTELConfig             `mapstructure:"otel"`
	Logs              cconfig.Logging                `mapstructure:"logs"`
	Server            cconfig.HttpServer             `mapstructure:"server"`
	PublisherEventBus cconfig.EventBusEngine         `mapstructure:"publisher_event_bus"`
	Storage           cconfig.PluggableStorageEngine `mapstructure:"storage"`

	KMSClient struct {
		cconfig.HTTPClient `mapstructure:",squash"`
	} `mapstructure:"kms_client"`

	CAClient struct {
		cconfig.HTTPClient `mapstructure:",squash"`
	} `mapstructure:"ca_client"`

	DevManagerClient struct {
		cconfig.HTTPClient `mapstructure:",squash"`
	} `mapstructure:"device_manager_client"`

	DownstreamCertificateFile string       `mapstructure:"downstream_cert_file"`
	WFX                       DMSWFXConfig `mapstructure:"wfx"`
}
