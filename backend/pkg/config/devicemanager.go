package config

import (
	"fmt"
	"time"

	cconfig "github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
)

type DeviceManagerConfig struct {
	OtelConfig            cconfig.OTELConfig             `mapstructure:"otel"`
	OpenAPI               cconfig.OpenAPIConfig          `mapstructure:"openapi"`
	Logs                  cconfig.Logging                `mapstructure:"logs"`
	Server                cconfig.HttpServer             `mapstructure:"server"`
	PublisherEventBus     cconfig.EventBusEngine         `mapstructure:"publisher_event_bus"`
	SubscriberEventBus    cconfig.EventBusEngine         `mapstructure:"subscriber_event_bus"`
	SubscriberDLQEventBus cconfig.EventBusEngine         `mapstructure:"subscriber_dlq_event_bus"`
	Storage               cconfig.PluggableStorageEngine `mapstructure:"storage"`
	SSEEnabled            bool                           `mapstructure:"sse_enabled"`
	CAClient              struct {
		cconfig.HTTPClient `mapstructure:",squash"`
	} `mapstructure:"ca_client"`
	AuthzClient AuthzClient `mapstructure:"authz_client"`
	// SSEMaxSubscribers bounds the SSE clients served at once. 0 uses the default of 1000. It is a single pool per
	// instance, shared by every device, user and tenant, with no per-user quota: size it for all expected viewers.
	SSEMaxSubscribers int `mapstructure:"sse_max_subscribers"`
	// SSEMaxStreamDuration bounds how long one SSE stream stays open, written as a Go duration such as "10m".
	// 0 uses the default of 10m.
	SSEMaxStreamDuration time.Duration `mapstructure:"sse_max_stream_duration"`
}

// ValidatedSSELimits returns the SSE limits as configured, 0 included so that the SSE hub applies its defaults.
func (c DeviceManagerConfig) ValidatedSSELimits() (maxSubscribers int, maxStreamDuration time.Duration, err error) {
	if c.SSEMaxSubscribers < 0 {
		return 0, 0, fmt.Errorf("sse_max_subscribers must not be negative, got %d", c.SSEMaxSubscribers)
	}
	if err := cconfig.CheckDuration("sse_max_stream_duration", c.SSEMaxStreamDuration); err != nil {
		return 0, 0, err
	}
	return c.SSEMaxSubscribers, c.SSEMaxStreamDuration, nil
}
