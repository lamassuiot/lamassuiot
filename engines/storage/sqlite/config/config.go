package config

type SQLitePSEConfig struct {
	DatabasePath string `mapstructure:"database_path"`
	InMemory     bool   `mapstructure:"in_memory"`
}
