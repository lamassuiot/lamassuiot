package config

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type TestServiceConfig struct {
	Logs        Logging    `mapstructure:"logs"`
	SecretValue Password   `mapstructure:"secret_value"`
	HttpServer  HttpServer `mapstructure:"http_server"`
}

func TestReadConfigWithDefaults(t *testing.T) {
	configFilePath := "testdata/test-config.yml"

	var defaults = TestServiceConfig{
		HttpServer: HttpServer{
			Port: 8080,
		},
		SecretValue: Password("mysuperpass"),
	}

	config, err := readConfig[TestServiceConfig](configFilePath, &defaults)
	assert.NoError(t, err)
	assert.NotEqual(t, defaults.HttpServer.Port, config.HttpServer.Port)
	assert.Equal(t, config.HttpServer.Port, 7777)                //Make sure config file has precedence
	assert.Equal(t, config.SecretValue, Password("mysuperpass")) //Make sure default value is used
	assert.Equal(t, config.HttpServer.ListenAddress, "0.0.0.0")
}

func TestReadConfig(t *testing.T) {
	// Test case 1: Valid config file
	configFilePath := "testdata/test-config.yml"

	expectedConfig := TestServiceConfig{
		Logs: Logging{
			Level: "info",
		},
	}

	config, err := readConfig[TestServiceConfig](configFilePath, nil)
	assert.NoError(t, err)
	assert.Equal(t, expectedConfig.Logs.Level, config.Logs.Level)
}

func TestReadConfigMissing(t *testing.T) {
	configFilePath := "testdata/config-missing.yml"
	config, err := readConfig[TestServiceConfig](configFilePath, nil)
	assert.Error(t, err)
	assert.Nil(t, config)
}

func TestReadConfigWrong(t *testing.T) {
	configFilePath := "testdata/wrong-config.yml"
	config, err := readConfig[TestServiceConfig](configFilePath, nil)
	assert.Error(t, err)
	assert.Nil(t, config)
}

func TestReadConfigWrongExtensionTxt(t *testing.T) {
	configFilePath := "testdata/wrong-config.txt"
	config, err := readConfig[TestServiceConfig](configFilePath, nil)
	assert.Error(t, err)
	assert.Nil(t, config)
}

func TestReadConfigUnexpected(t *testing.T) {
	configFilePath := "testdata/unexpected-config.yml"
	config, err := readConfig[TestServiceConfig](configFilePath, nil)
	assert.Error(t, err)
	assert.Nil(t, config)
}

func TestLoadConfigFromEnv(t *testing.T) {
	t.Cleanup(func() {
		os.Unsetenv("LAMASSU_CONFIG_FILE")
	})

	configFilePath := "testdata/test-config.yml"
	os.Setenv("LAMASSU_CONFIG_FILE", configFilePath)

	expectedConfig := TestServiceConfig{
		Logs: Logging{
			Level: "info",
		},
	}

	config, err := LoadConfig[TestServiceConfig](nil)
	assert.NoError(t, err)
	assert.Equal(t, expectedConfig.Logs.Level, config.Logs.Level)
}

func TestLoadConfigFromEnvMissingFile(t *testing.T) {
	t.Cleanup(func() {
		os.Unsetenv("LAMASSU_CONFIG_FILE")
	})

	configFilePath := "testdata/test-config-missing.yml"
	os.Setenv("LAMASSU_CONFIG_FILE", configFilePath)

	config, err := LoadConfig[TestServiceConfig](nil)
	assert.Error(t, err)
	assert.Nil(t, config)
}

func TestLoadConfigFromUnsetEnv(t *testing.T) {
	config, err := LoadConfig[TestServiceConfig](nil)
	assert.Error(t, err)
	assert.Nil(t, config)
}

// TestReadConfigIssuerWithDots comprueba que un issuer con puntos como clave de
// issuer_jwks_urls se carga sin partirse y sin romper el resto de la
// configuración anidada (005 T2).
func TestReadConfigIssuerWithDots(t *testing.T) {
	var defaults = TestServiceConfig{
		SecretValue: Password("mysuperpass"),
	}

	config, err := readConfig[TestServiceConfig]("testdata/issuer-dots-config.yml", &defaults)
	assert.NoError(t, err)
	if !assert.NotNil(t, config) {
		return
	}

	assert.Equal(t, map[string]string{
		"https://keycloak.example.com/realms/lamassu": "https://keycloak.example.com/realms/lamassu/protocol/openid-connect/certs",
		"https://login.example.org/tenant.a/v2.0":     "https://login.example.org/tenant.a/discovery/v2.0/keys",
	}, config.HttpServer.Authentication.JWT.IssuerJWKSURLs)
	assert.True(t, config.HttpServer.Authentication.JWT.Enabled)
	assert.Equal(t, "lamassu", config.HttpServer.Authentication.JWT.Audience)
	assert.Equal(t, []string{"RS256"}, config.HttpServer.Authentication.JWT.AllowedAlgorithms)
	assert.Equal(t, 5*time.Minute, config.HttpServer.Authentication.JWT.JWKSCacheTTL)
	assert.Equal(t, 7777, config.HttpServer.Port)
	assert.Equal(t, "0.0.0.0", config.HttpServer.ListenAddress)
	assert.Equal(t, LogLevel("info"), config.Logs.Level)
	assert.Equal(t, Password("mysuperpass"), config.SecretValue)
}
