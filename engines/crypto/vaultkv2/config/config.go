package config

import (
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
)

type HashicorpVaultCryptoEngineConfig struct {
	HashicorpVaultSDK `mapstructure:",squash"`
	ID                string                 `mapstructure:"id"`
	Metadata          map[string]interface{} `mapstructure:"metadata"`
}
type HashicorpVaultSDK struct {
	RoleID                string            `mapstructure:"role_id"`
	SecretID              config.Password   `mapstructure:"secret_id"`
	AutoUnsealEnabled     bool              `mapstructure:"auto_unseal_enabled"`
	AutoUnsealKeys        []config.Password `mapstructure:"auto_unseal_keys"`
	MountPath             string            `mapstructure:"mount_path"`
	config.HTTPConnection `mapstructure:",squash"`
}
