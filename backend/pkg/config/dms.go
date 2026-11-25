package config

import (
	"fmt"

	cconfig "github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
)

type DMSconfig struct {
	OtelConfig        cconfig.OTELConfig             `mapstructure:"otel"`
	OpenAPI           cconfig.OpenAPIConfig          `mapstructure:"openapi"`
	Logs              cconfig.Logging                `mapstructure:"logs"`
	Server            cconfig.HttpServer             `mapstructure:"server"`
	PublisherEventBus cconfig.EventBusEngine         `mapstructure:"publisher_event_bus"`
	Storage           cconfig.PluggableStorageEngine `mapstructure:"storage"`

	CAClient struct {
		cconfig.HTTPClient `mapstructure:",squash"`
	} `mapstructure:"ca_client"`

	DevManagerClient struct {
		cconfig.HTTPClient `mapstructure:",squash"`
	} `mapstructure:"device_manager_client"`

	AuthzClient               AuthzClient    `mapstructure:"authz_client"`
	DownstreamCertificateFile string         `mapstructure:"downstream_cert_file"`
	CRLCache                  CRLCacheConfig `mapstructure:"crl_cache"`
}

// CRLCacheConfig configures the in-memory cache of the CRLs downloaded for EST client certificate revocation checks.
type CRLCacheConfig struct {
	// MaxSizeMB bounds the estimated memory of the cached CRLs, in megabytes. 0 uses the default of 1024.
	MaxSizeMB int `mapstructure:"max_size_mb"`
}

// MaxBytes returns the configured budget in bytes, or 0 when unset so that the service applies its default.
func (c CRLCacheConfig) MaxBytes() (uint64, error) {
	if c.MaxSizeMB < 0 {
		return 0, fmt.Errorf("crl_cache.max_size_mb must not be negative, got %d", c.MaxSizeMB)
	}
	return uint64(c.MaxSizeMB) << 20, nil
}
