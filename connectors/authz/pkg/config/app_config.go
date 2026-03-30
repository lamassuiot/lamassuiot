package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// AppConfig is the top-level YAML configuration for the authz service.
type AppConfig struct {
	Debug       bool                     `yaml:"debug"`
	Schemas     map[string]string        `yaml:"schemas"`
	Credentials map[string]DBCredentials `yaml:"credentials"`
}

// DBCredentials holds PostgreSQL connection parameters for a single database.
type DBCredentials struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Database string `yaml:"database"`
}

// LoadAppConfig reads and parses the YAML config file at the given path.
func LoadAppConfig(path string) (*AppConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %q: %w", path, err)
	}

	var cfg AppConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file %q: %w", path, err)
	}

	return &cfg, nil
}
