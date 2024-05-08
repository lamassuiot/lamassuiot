package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReadConfig(t *testing.T) {
	// Test case 1: Valid config file
	configFilePath := "testdata/test-config.yml"

	expectedConfig := CAConfig{
		Logs: BaseConfigLogging{
			Level: "info",
		},
	}

	config, err := readConfig[CAConfig](configFilePath)
	assert.NoError(t, err)
	assert.Equal(t, expectedConfig.Logs.Level, config.Logs.Level)
}

func TestReadConfigMissing(t *testing.T) {

	configFilePath := "testdata/config-missing.yml"
	config, err := readConfig[CAConfig](configFilePath)
	assert.Error(t, err)
	assert.Nil(t, config)
}

func TestReadConfigWrong(t *testing.T) {

	configFilePath := "testdata/wrong-config.yml"
	config, err := readConfig[IotAWS](configFilePath)
	assert.Error(t, err)
	assert.Nil(t, config)
}

func TestReadConfigWrongExtensionTxt(t *testing.T) {

	configFilePath := "testdata/wrong-config.txt"
	config, err := readConfig[IotAWS](configFilePath)
	assert.Error(t, err)
	assert.Nil(t, config)
}

func TestReadConfigUnexpected(t *testing.T) {

	configFilePath := "testdata/unexpected-config.yml"
	config, err := readConfig[IotAWS](configFilePath)
	assert.Error(t, err)
	assert.Nil(t, config)
}

func TestLoadConfigFromEnv(t *testing.T) {
	t.Cleanup(func() {
		os.Unsetenv("LAMASSU_CONFIG_FILE")
	})

	configFilePath := "testdata/test-config.yml"
	os.Setenv("LAMASSU_CONFIG_FILE", configFilePath)

	expectedConfig := CAConfig{
		Logs: BaseConfigLogging{
			Level: "info",
		},
	}

	config, err := LoadConfig[CAConfig]()
	assert.NoError(t, err)
	assert.Equal(t, expectedConfig.Logs.Level, config.Logs.Level)
}

func TestLoadConfigFromEnvMissingFile(t *testing.T) {
	t.Cleanup(func() {
		os.Unsetenv("LAMASSU_CONFIG_FILE")
	})

	configFilePath := "testdata/test-config-missing.yml"
	os.Setenv("LAMASSU_CONFIG_FILE", configFilePath)

	config, err := LoadConfig[CAConfig]()
	assert.Error(t, err)
	assert.Nil(t, config)
}

func TestLoadConfigFromUnsetEnv(t *testing.T) {
	config, err := LoadConfig[CAConfig]()
	assert.Error(t, err)
	assert.Nil(t, config)
}
