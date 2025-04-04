package config

type Authorization struct {
	Disable     bool              `mapstructure:"disable"`
	RolesClaim  string            `mapstructure:"roles_claim"`
	RoleMapping map[string]string `mapstructure:"role_mapping"`
}
