package pkcs11

import (
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
)

type PKCS11Config struct {
	TokenLabel         string                   `mapstructure:"token"`
	TokenPin           config.Password          `mapstructure:"pin"`
	ModulePath         string                   `mapstructure:"module_path"`
	ModuleExtraOptions PKCS11ModuleExtraOptions `mapstructure:"module_extra_options"`
}

type PKCS11ModuleExtraOptions struct {
	Env map[string]string `mapstructure:"env"`
}
