package config

import (
	"github.com/lamassuiot/lamassuiot/v2/core/pkg/config"
)

type PKCS11Config struct {
	TokenLabel         string                   `mapstructure:"token"`
	TokenPin           config.Password          `mapstructure:"pin"`
	ModulePath         string                   `mapstructure:"module_path"`
	ModuleExtraOptions PKCS11ModuleExtraOptions `mapstructure:"module_extra_options"`
}

type PKCS11EngineConfig struct {
	PKCS11Config `mapstructure:",squash"`
	ID           string                 `mapstructure:"id"`
	Metadata     map[string]interface{} `mapstructure:"metadata"`
}

type PKCS11ModuleExtraOptions struct {
	Env map[string]string `mapstructure:"env"`
}
