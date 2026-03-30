package config

import (
	"os"
	"strconv"
)

type ServerConfig struct {
	Host        string
	Port        int
	SchemaPath  string
	PolicyPaths []string
	DatabaseDSN string
	EnableCORS  bool
	LogLevel    string
}

func LoadServerConfig() *ServerConfig {
	port, _ := strconv.Atoi(getEnv("PORT", "8080"))

	return &ServerConfig{
		Host:       getEnv("HOST", "0.0.0.0"),
		Port:       port,
		SchemaPath: getEnv("SCHEMA_PATH", "/home/ubuntu/dev/authz2/examples/iot/schemas.json"),
		PolicyPaths: []string{
			getEnv("POLICY_PATH", "/home/ubuntu/dev/authz2/examples/iot/policies.json"),
		},
		DatabaseDSN: getEnv("DATABASE_DSN", ""),
		EnableCORS:  getEnv("ENABLE_CORS", "true") == "true",
		LogLevel:    getEnv("LOG_LEVEL", "info"),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
