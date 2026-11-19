package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

type CredentialOverrideConfig struct {
	Storage           PluggableStorageEngine `mapstructure:"storage"`
	PublisherEventBus EventBusEngine         `mapstructure:"publisher_event_bus"`
	SMTPServer        struct {
		Username string `mapstructure:"username"`
		Password string `mapstructure:"password"`
		Host     string `mapstructure:"host"`
	} `mapstructure:"smtp_server"`
	AuthzDB     PluggableStorageEngine            `mapstructure:"authz_db"`
	Credentials map[string]PluggableStorageEngine `mapstructure:"credentials"`
}

type testPostgresConfig struct {
	Password Password `mapstructure:"password"`
}

type testAMQPConfig struct {
	BasicAuth struct {
		Password Password `mapstructure:"password"`
	} `mapstructure:"basic_auth"`
}

func TestCredentialSchemaEnvPart(t *testing.T) {
	assert.Equal(t, "PKI", credentialSchemaEnvPart("pki"))
	assert.Equal(t, "PKI_V2", credentialSchemaEnvPart("pki-v2"))
	assert.Equal(t, "PKI_V2", credentialSchemaEnvPart("pki.v2"))
}

func TestReadConfigRejectsCredentialSchemaEnvironmentNameCollisions(t *testing.T) {
	_, err := readConfig[CredentialOverrideConfig](writeCredentialConfig(t, `
credentials:
  pki.v2:
    provider: postgres
  pki_v2:
    provider: postgres
`), nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "pki.v2")
	assert.Contains(t, err.Error(), "pki_v2")
	assert.Contains(t, err.Error(), "produce the same environment variable name")
}

func TestReadConfigIgnoresCredentialEnvironmentVariablesForAbsentSchemas(t *testing.T) {
	t.Setenv("LAMASSU_AUTHZ_CREDENTIALS_FOO_USERNAME", "env-foo-user")

	config, err := readConfig[CredentialOverrideConfig](writeCredentialConfig(t, `
credentials:
  pki:
    provider: postgres
    username: yaml-pki-user
`), nil)
	require.NoError(t, err)

	require.Len(t, config.Credentials, 1)
	assert.Equal(t, "yaml-pki-user", config.Credentials["pki"].Config["username"])
	_, exists := config.Credentials["foo"]
	assert.False(t, exists)
}

func TestReadConfigRejectsEmptyCredentialEnvironmentVariablesForSchema(t *testing.T) {
	t.Setenv("LAMASSU_AUTHZ_CREDENTIALS_PKI_PASSWORD", "")

	_, err := readConfig[CredentialOverrideConfig](writeCredentialConfig(t, `
credentials:
  pki:
    provider: postgres
    password: yaml-pki-password
`), nil)

	require.ErrorContains(t, err, "LAMASSU_AUTHZ_CREDENTIALS_PKI_PASSWORD is set but empty")
}

func TestReadConfigAllowsEmptyCredentialEnvironmentVariableWithEmptyYAMLValue(t *testing.T) {
	t.Setenv("LAMASSU_POSTGRES_PASSWORD", "")

	config, err := readConfig[CredentialOverrideConfig](writeCredentialConfig(t, `
storage:
  provider: postgres
  password: ""
`), nil)
	require.NoError(t, err)
	assert.Equal(t, "", config.Storage.Config["password"])
}

func writeCredentialConfig(t *testing.T, config string) string {
	t.Helper()
	configPath := t.TempDir() + "/config.yml"
	require.NoError(t, os.WriteFile(configPath, []byte(config), 0600))
	return configPath
}

func TestReadConfigCredentialEnvironmentOverrides(t *testing.T) {
	t.Setenv("LAMASSU_POSTGRES_USERNAME", "env-pg-user")
	t.Setenv("LAMASSU_POSTGRES_PASSWORD", "env-pg-password")
	t.Setenv("LAMASSU_AMQP_USERNAME", "env-amqp-user")
	t.Setenv("LAMASSU_AMQP_PASSWORD", "env-amqp-password")
	t.Setenv("LAMASSU_SMTP_USERNAME", "env-smtp-user")
	t.Setenv("LAMASSU_SMTP_PASSWORD", "env-smtp-password")
	t.Setenv("LAMASSU_AUTHZ_DB_USERNAME", "env-authz-user")
	t.Setenv("LAMASSU_AUTHZ_DB_PASSWORD", "env-authz-password")
	t.Setenv("LAMASSU_AUTHZ_CREDENTIALS_PKI_USERNAME", "env-pki-user")
	t.Setenv("LAMASSU_AUTHZ_CREDENTIALS_PKI_PASSWORD", "env-pki-password")
	t.Setenv("LAMASSU_POSTGRES_HOSTNAME", "must-not-be-used")

	config, err := readConfig[CredentialOverrideConfig](writeCredentialConfig(t, `
storage:
  provider: postgres
  hostname: yaml-host
  port: 5432
  username: yaml-pg-user
  password: yaml-pg-password
publisher_event_bus:
  provider: amqp
  hostname: yaml-host
  port: 5672
  basic_auth:
    enabled: true
    username: yaml-amqp-user
    password: yaml-amqp-password
smtp_server:
  host: yaml-smtp-host
  username: yaml-smtp-user
  password: yaml-smtp-password
authz_db:
  provider: postgres
  username: yaml-authz-user
  password: yaml-authz-password
credentials:
  pki:
    provider: postgres
    username: yaml-pki-user
    password: yaml-pki-password
`), nil)
	require.NoError(t, err)

	assert.Equal(t, "env-pg-user", config.Storage.Config["username"])
	assert.Equal(t, "env-pg-password", config.Storage.Config["password"])
	assert.Equal(t, "env-amqp-user", config.PublisherEventBus.Config["basic_auth"].(map[string]any)["username"])
	assert.Equal(t, "env-amqp-password", config.PublisherEventBus.Config["basic_auth"].(map[string]any)["password"])
	assert.Equal(t, "env-smtp-user", config.SMTPServer.Username)
	assert.Equal(t, "env-smtp-password", config.SMTPServer.Password)
	assert.Equal(t, "env-authz-user", config.AuthzDB.Config["username"])
	assert.Equal(t, "env-authz-password", config.AuthzDB.Config["password"])
	assert.Equal(t, "env-pki-user", config.Credentials["pki"].Config["username"])
	assert.Equal(t, "env-pki-password", config.Credentials["pki"].Config["password"])

	assert.Equal(t, "yaml-host", config.Storage.Config["hostname"])
	assert.Equal(t, 5432, config.Storage.Config["port"])
	assert.Equal(t, "yaml-host", config.PublisherEventBus.Config["hostname"])
	assert.Equal(t, "yaml-smtp-host", config.SMTPServer.Host)

	pg, err := DecodeStruct[testPostgresConfig](config.Storage.Config)
	require.NoError(t, err)
	assert.Equal(t, Password("env-pg-password"), pg.Password)

	amqp, err := DecodeStruct[testAMQPConfig](config.PublisherEventBus.Config)
	require.NoError(t, err)
	assert.Equal(t, Password("env-amqp-password"), amqp.BasicAuth.Password)
}

func TestReadConfigCredentialEnvironmentVariablesCanSupplyMissingValues(t *testing.T) {
	t.Setenv("LAMASSU_POSTGRES_PASSWORD", "env-pg-password")
	t.Setenv("LAMASSU_AMQP_PASSWORD", "env-amqp-password")
	t.Setenv("LAMASSU_SMTP_PASSWORD", "env-smtp-password")
	t.Setenv("LAMASSU_AUTHZ_DB_PASSWORD", "env-authz-password")
	t.Setenv("LAMASSU_AUTHZ_CREDENTIALS_PKI_PASSWORD", "env-pki-password")

	config, err := readConfig[CredentialOverrideConfig](writeCredentialConfig(t, `
storage:
  provider: postgres
  hostname: yaml-host
  port: 5432
publisher_event_bus:
  provider: amqp
  hostname: yaml-host
  port: 5672
  basic_auth:
    enabled: true
smtp_server:
  host: yaml-smtp-host
authz_db:
  provider: postgres
credentials:
  pki:
    provider: postgres
`), nil)
	require.NoError(t, err)

	assert.Equal(t, "env-pg-password", config.Storage.Config["password"])
	assert.Equal(t, "env-amqp-password", config.PublisherEventBus.Config["basic_auth"].(map[string]any)["password"])
	assert.Equal(t, "env-smtp-password", config.SMTPServer.Password)
	assert.Equal(t, "env-authz-password", config.AuthzDB.Config["password"])
	assert.Equal(t, "env-pki-password", config.Credentials["pki"].Config["password"])
}

func TestReadConfigCredentialEnvironmentOverridesSubscriberBuses(t *testing.T) {
	t.Setenv("LAMASSU_AMQP_USERNAME", "env-amqp-user")
	t.Setenv("LAMASSU_AMQP_PASSWORD", "env-amqp-password")

	config, err := readConfig[struct {
		SubscriberEventBus    EventBusEngine `mapstructure:"subscriber_event_bus"`
		SubscriberDLQEventBus EventBusEngine `mapstructure:"subscriber_dlq_event_bus"`
	}](writeCredentialConfig(t, `
subscriber_event_bus:
  provider: amqp
  basic_auth:
    username: yaml-user
    password: yaml-password
subscriber_dlq_event_bus:
  provider: amqp
  basic_auth:
    username: yaml-user
    password: yaml-password
`), nil)
	require.NoError(t, err)

	for _, eventBus := range []EventBusEngine{config.SubscriberEventBus, config.SubscriberDLQEventBus} {
		auth := eventBus.Config["basic_auth"].(map[string]any)
		assert.Equal(t, "env-amqp-user", auth["username"])
		assert.Equal(t, "env-amqp-password", auth["password"])
	}
}

func TestReadConfigUnsetCredentialEnvironmentVariablesPreserveYAML(t *testing.T) {
	credentialEnvVars := []string{
		"LAMASSU_POSTGRES_USERNAME",
		"LAMASSU_POSTGRES_PASSWORD",
		"LAMASSU_AMQP_USERNAME",
		"LAMASSU_AMQP_PASSWORD",
		"LAMASSU_SMTP_USERNAME",
		"LAMASSU_SMTP_PASSWORD",
	}
	originalEnv := make(map[string]string, len(credentialEnvVars))
	originallySet := make(map[string]bool, len(credentialEnvVars))
	for _, envName := range credentialEnvVars {
		if value, ok := os.LookupEnv(envName); ok {
			originalEnv[envName] = value
			originallySet[envName] = true
		}
		require.NoError(t, os.Unsetenv(envName))
	}
	t.Cleanup(func() {
		for _, envName := range credentialEnvVars {
			if originallySet[envName] {
				assert.NoError(t, os.Setenv(envName, originalEnv[envName]))
			} else {
				assert.NoError(t, os.Unsetenv(envName))
			}
		}
	})

	config, err := readConfig[CredentialOverrideConfig](writeCredentialConfig(t, `
storage:
  provider: postgres
  hostname: yaml-host
  port: 5432
  username: yaml-pg-user
  password: yaml-pg-password
publisher_event_bus:
  provider: amqp
  hostname: yaml-host
  port: 5672
  basic_auth:
    enabled: true
    username: yaml-amqp-user
    password: yaml-amqp-password
smtp_server:
  host: yaml-smtp-host
  username: yaml-smtp-user
  password: yaml-smtp-password
`), nil)
	require.NoError(t, err)

	assert.Equal(t, "yaml-pg-user", config.Storage.Config["username"])
	assert.Equal(t, "yaml-pg-password", config.Storage.Config["password"])
	assert.Equal(t, "yaml-amqp-user", config.PublisherEventBus.Config["basic_auth"].(map[string]any)["username"])
	assert.Equal(t, "yaml-amqp-password", config.PublisherEventBus.Config["basic_auth"].(map[string]any)["password"])
	assert.Equal(t, "yaml-smtp-user", config.SMTPServer.Username)
	assert.Equal(t, "yaml-smtp-password", config.SMTPServer.Password)
}

func TestReadConfigEmptyCredentialEnvironmentVariablesFailWhenYAMLValueExists(t *testing.T) {
	credentialEnvVars := []string{
		"LAMASSU_POSTGRES_USERNAME",
		"LAMASSU_POSTGRES_PASSWORD",
		"LAMASSU_AMQP_USERNAME",
		"LAMASSU_AMQP_PASSWORD",
		"LAMASSU_SMTP_USERNAME",
		"LAMASSU_SMTP_PASSWORD",
	}
	originalEnv := make(map[string]string, len(credentialEnvVars))
	originallySet := make(map[string]bool, len(credentialEnvVars))
	for _, envName := range credentialEnvVars {
		if value, ok := os.LookupEnv(envName); ok {
			originalEnv[envName] = value
			originallySet[envName] = true
		}
		require.NoError(t, os.Unsetenv(envName))
	}
	t.Cleanup(func() {
		for _, envName := range credentialEnvVars {
			if originallySet[envName] {
				assert.NoError(t, os.Setenv(envName, originalEnv[envName]))
			} else {
				assert.NoError(t, os.Unsetenv(envName))
			}
		}
	})

	t.Setenv("LAMASSU_POSTGRES_PASSWORD", "")
	t.Setenv("LAMASSU_AMQP_PASSWORD", "")
	t.Setenv("LAMASSU_SMTP_PASSWORD", "")

	_, err := readConfig[CredentialOverrideConfig](writeCredentialConfig(t, `
storage:
  provider: postgres
  hostname: yaml-host
  port: 5432
  username: yaml-pg-user
  password: yaml-pg-password
publisher_event_bus:
  provider: amqp
  hostname: yaml-host
  port: 5672
  basic_auth:
    enabled: true
    username: yaml-amqp-user
    password: yaml-amqp-password
smtp_server:
  host: yaml-smtp-host
  username: yaml-smtp-user
  password: yaml-smtp-password
`), nil)
	require.ErrorContains(t, err, "LAMASSU_POSTGRES_PASSWORD is set but empty")
}
