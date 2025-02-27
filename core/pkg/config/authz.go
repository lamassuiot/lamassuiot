package config

type Authorization struct {
	Enabled     bool              `mapstructure:"enabled"`
	RolesClaim  string            `mapstructure:"roles_claim"`
	RoleMapping map[string]string `mapstructure:"role_mapping"`
}
