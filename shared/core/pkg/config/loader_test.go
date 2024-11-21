package config

import (
	"os"
	"testing"

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
