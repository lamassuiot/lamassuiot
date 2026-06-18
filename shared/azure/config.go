package azure

import cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"

type AzureAuthenticationMethod string

const (
	Secret      AzureAuthenticationMethod = "secret"
	Certificate AzureAuthenticationMethod = "certificate"
	Emulator    AzureAuthenticationMethod = "emulator"
)

type AzureSDKConfig struct {
	AzureAuthenticationMethod AzureAuthenticationMethod `mapstructure:"auth_method"`
	VaultURL                  string                    `mapstructure:"vault_url"`
	// AllowHTTP permits sending credentials over plain HTTP.
	// Required when VaultURL uses http:// (e.g. floci-az or Azurite in dev mode).
	// Do not enable in production.
	AllowHTTP bool `mapstructure:"allow_http"`
	// Service principal fields (Secret / Certificate auth)
	ClientID        string           `mapstructure:"client_id"`
	TenantID        string           `mapstructure:"tenant_id"`
	ClientSecret    cconfig.Password `mapstructure:"client_secret"`
	CertificatePath string           `mapstructure:"certificate_path"`
	KeyPath         string           `mapstructure:"key_path"`
}
