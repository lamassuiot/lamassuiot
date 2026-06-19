package config

import cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"

// BootstrapEntry defines a principal and the policies to pre-grant on first startup.
// All operations are idempotent — safe to leave in config permanently.
type BootstrapEntry struct {
	// PrincipalID is the unique identifier for the principal (e.g. "oidc:haritzsaiz").
	PrincipalID string `mapstructure:"principal_id" json:"principal_id"`
	// PrincipalName is the human-readable display name. Defaults to PrincipalID if empty.
	PrincipalName string `mapstructure:"principal_name" json:"principal_name,omitempty"`
	// PrincipalType is the credential type: "oidc" or "x509".
	PrincipalType string `mapstructure:"principal_type" json:"principal_type"`
	// AuthConfig holds type-specific matching config (e.g. claim name/value for OIDC).
	AuthConfig map[string]interface{} `mapstructure:"auth_config" json:"auth_config,omitempty"`
	// PolicyIDs is the list of policy IDs to grant to this principal.
	PolicyIDs []string `mapstructure:"policy_ids" json:"policy_ids,omitempty"`
}

// AuthzConfig is the top-level configuration for the authz service.
// Loaded via cconfig.LoadConfig[AuthzConfig](nil) — reads from LAMASSU_CONFIG_FILE env var
// or falls back to /etc/lamassuiot/config.yml.
type AuthzConfig struct {
	OtelConfig         cconfig.OTELConfig     `mapstructure:"otel"`
	Logs               cconfig.Logging        `mapstructure:"logs"`
	Server             cconfig.HttpServer     `mapstructure:"server"`
	PublisherEventBus  cconfig.EventBusEngine `mapstructure:"publisher_event_bus"`
	SubscriberEventBus cconfig.EventBusEngine `mapstructure:"subscriber_event_bus"`
	Schemas            map[string]string      `mapstructure:"schemas"`
	// Credentials holds per-schema engine Postgres connections (provider must be "postgres").
	Credentials map[string]cconfig.PluggableStorageEngine `mapstructure:"credentials"`
	// AuthzDB is the Postgres database for principals, grants, and policies.
	AuthzDB    cconfig.PluggableStorageEngine `mapstructure:"authz_db"`
	PreloadDir string                         `mapstructure:"preload_dir"`
	// Bootstrap seeds principals and policy grants on startup. Idempotent.
	Bootstrap []BootstrapEntry `mapstructure:"bootstrap"`
	// URL to fetch JSON Web Key Sets for verifying JWT tokens.
	JWKSURL             string `mapstructure:"jwks_url"`
	EnableJWTValidation bool   `mapstructure:"enable_jwt_validation"`
	// HTTPSchemas is a list of file paths to HTTP schema JSON files.
	// Each file contains an array of HTTPSchemaDefinition objects that describe
	// REST API routes for use with the Envoy ext_authz endpoint.
	HTTPSchemas []string `mapstructure:"http_schemas"`
}
