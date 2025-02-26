package config

import "github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes/middlewares/authz"

type Authorization struct {
	Enabled     bool                  `mapstructure:"enabled"`
	RolesClaim  string                `mapstructure:"roles_claim"`
	RoleMapping map[authz.Role]string `mapstructure:"role_mapping"`
}
