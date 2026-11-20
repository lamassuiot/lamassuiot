package config

import cconfig "github.com/lamassuiot/lamassuiot/v4/core/pkg/config"

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

	AuthzClient               AuthzClient        `mapstructure:"authz_client"`
	DownstreamCertificateFile string             `mapstructure:"downstream_cert_file"`
	AuthzPrincipals           DMSAuthzPrincipals `mapstructure:"authz_principals"`
}

// DMSAuthzPrincipals lets a DMS keep, through authz_client, the principal that trusts its enrollment CA.
type DMSAuthzPrincipals struct {
	Enabled                  bool              `mapstructure:"enabled"`
	PolicyIDs                []string          `mapstructure:"policy_ids"`                 // granted to every such principal; a DMS cannot choose others
	SubjectAttributeMappings map[string]string `mapstructure:"subject_attribute_mappings"` // e.g. device_id: x509.subject.cn
}
