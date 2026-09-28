package config

import cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"

type TenantManagerConfig struct {
	Logs    cconfig.Logging                `mapstructure:"logs"`
	Server  cconfig.HttpServer             `mapstructure:"server"`
	Storage cconfig.PluggableStorageEngine `mapstructure:"storage"`
	// Provisioners are the only identities allowed to create organizations and
	// tenants and to change tenant status. They get no access to tenant data.
	Provisioners []TenantManagerProvisioner `mapstructure:"provisioners"`
}

type TenantManagerProvisioner struct {
	Issuer  string `mapstructure:"issuer"`
	Subject string `mapstructure:"subject"`
}
