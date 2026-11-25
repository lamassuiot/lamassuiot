package config

import (
	"fmt"
	"time"

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
	// MaxSizeMB bounds the estimated memory of the cached CRLs, in megabytes. 0 uses the default of 256.
	MaxSizeMB int `mapstructure:"max_size_mb"`
	// MaxTTL bounds how long a downloaded CRL is reused, written as a Go duration such as "1h" or "30m". A CRL is
	// never kept past its nextUpdate, so the effective TTL is the smaller of the two. 0 uses the default of 1h.
	MaxTTL time.Duration `mapstructure:"max_ttl"`
}

// MaxBytes returns the configured budget in bytes, or 0 when unset so that the service applies its default.
func (c CRLCacheConfig) MaxBytes() (uint64, error) {
	if c.MaxSizeMB < 0 {
		return 0, fmt.Errorf("crl_cache.max_size_mb must not be negative, got %d", c.MaxSizeMB)
	}
	return uint64(c.MaxSizeMB) << 20, nil
}

// ValidatedMaxTTL returns the configured maximum TTL, or 0 when unset so that the service applies its default.
func (c CRLCacheConfig) ValidatedMaxTTL() (time.Duration, error) {
	if c.MaxTTL < 0 {
		return 0, fmt.Errorf("crl_cache.max_ttl must not be negative, got %s", c.MaxTTL)
	}
	return c.MaxTTL, nil
}
