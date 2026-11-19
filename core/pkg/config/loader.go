package config

import (
	"fmt"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
)

func DecodeStruct[E any](source any) (E, error) {
	var target E
	err := mapstructure.Decode(source, &target)
	if err != nil {
		var zero E
		return zero, fmt.Errorf("could not decode struct: %w", err)
	}
	return target, nil
}

func EncodeStruct[E any](source E) (map[string]any, error) {
	var target map[string]any
	err := mapstructure.Decode(source, &target)
	if err != nil {
		return nil, fmt.Errorf("could not decode struct: %w", err)
	}
	return target, nil
}

type credentialEnvBinding struct {
	configKey string
	envName   string
}

// credentialEnvBindings is the allowlist of fixed credential paths that may
// be overridden by the process environment. Keep this explicit: enabling
// AutomaticEnv would also expose non-secret configuration to implicit
// overrides.
var credentialEnvBindings = []credentialEnvBinding{
	{configKey: "storage.username", envName: "LAMASSU_POSTGRES_USERNAME"},
	{configKey: "storage.password", envName: "LAMASSU_POSTGRES_PASSWORD"},
	{configKey: "authz_db.username", envName: "LAMASSU_AUTHZ_DB_USERNAME"},
	{configKey: "authz_db.password", envName: "LAMASSU_AUTHZ_DB_PASSWORD"},
	{configKey: "publisher_event_bus.basic_auth.username", envName: "LAMASSU_AMQP_USERNAME"},
	{configKey: "publisher_event_bus.basic_auth.password", envName: "LAMASSU_AMQP_PASSWORD"},
	{configKey: "subscriber_event_bus.basic_auth.username", envName: "LAMASSU_AMQP_USERNAME"},
	{configKey: "subscriber_event_bus.basic_auth.password", envName: "LAMASSU_AMQP_PASSWORD"},
	{configKey: "subscriber_dlq_event_bus.basic_auth.username", envName: "LAMASSU_AMQP_USERNAME"},
	{configKey: "subscriber_dlq_event_bus.basic_auth.password", envName: "LAMASSU_AMQP_PASSWORD"},
	{configKey: "smtp_server.username", envName: "LAMASSU_SMTP_USERNAME"},
	{configKey: "smtp_server.password", envName: "LAMASSU_SMTP_PASSWORD"},
}

var dynamicCredentialFields = []string{"username", "password"}

func rejectEmptyCredentialEnv(vp *viper.Viper, configKey, envName string) error {
	if value, exists := os.LookupEnv(envName); exists && value == "" && vp.GetString(configKey) != "" {
		return fmt.Errorf("credential environment variable %s is set but empty while configuration key %s has a value", envName, configKey)
	}
	return nil
}

func credentialSchemaEnvPart(schema string) string {
	return strings.ToUpper(strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			return r
		}
		return '_'
	}, schema))
}

func bindCredentialEnv(vp *viper.Viper) error {
	for _, binding := range credentialEnvBindings {
		if err := vp.BindEnv(binding.configKey, binding.envName); err != nil {
			return fmt.Errorf("could not bind environment variable %s to %s: %w", binding.envName, binding.configKey, err)
		}
		if err := rejectEmptyCredentialEnv(vp, binding.configKey, binding.envName); err != nil {
			return err
		}
	}

	credentials := vp.GetStringMap("credentials")
	envNames := make(map[string]string, len(credentials))
	for schema := range credentials {
		envPart := credentialSchemaEnvPart(schema)
		envPrefix := "LAMASSU_AUTHZ_CREDENTIALS_" + envPart
		if previousSchema, exists := envNames[envPart]; exists && previousSchema != schema {
			return fmt.Errorf("authz credential schemas %q and %q produce the same environment variable name", previousSchema, schema)
		}
		envNames[envPart] = schema

		for _, field := range dynamicCredentialFields {
			key := "credentials." + schema + "." + field
			env := envPrefix + "_" + strings.ToUpper(field)
			if err := vp.BindEnv(key, env); err != nil {
				return fmt.Errorf("could not bind environment variable %s to %s: %w", env, key, err)
			}
			if err := rejectEmptyCredentialEnv(vp, key, env); err != nil {
				return err
			}
		}
	}

	return nil
}

func readConfig[E any](configFilePath string, defaults *E) (*E, error) {
	vp := viper.New()
	defaultsMap := map[string]any{}

	if defaults != nil {
		mapstructure.Decode(defaults, &defaultsMap)

		for key, value := range defaultsMap {
			if value != nil && value != "" {
				vp.SetDefault(key, value)
			}

		}
	}

	vp.SetConfigFile(configFilePath)
	if err := vp.ReadInConfig(); err != nil {
		// This error is not raised by viper when the file is not found when using SetConfigFile.
		// Check PR https://github.com/spf13/viper/pull/1803
		/* if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found; ignore error if desired
			return nil, fmt.Errorf("config file not found: %s", err)
		}

		} else { */
		// Config file was found but another error was produced
		return nil, fmt.Errorf("error while processing config file: %w", err)
		// }
	}

	if err := bindCredentialEnv(vp); err != nil {
		return nil, fmt.Errorf("could not configure credential environment overrides: %w", err)
	}

	var config E
	err := vp.Unmarshal(&config)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal config: %w", err)
	}

	return &config, nil
}

func LoadConfig[E any](defaults *E) (*E, error) {
	var err error
	var conf *E

	configFileEnvVar := "LAMASSU_CONFIG_FILE"
	configFileEnv := os.Getenv(configFileEnvVar)
	loadStandardPaths := true

	if configFileEnv != "" {
		loadStandardPaths = false
		log.Infof("loading config file from %s", configFileEnv)
		conf, err = readConfig[E](configFileEnv, defaults)

		if err != nil {
			log.Warnf("failed to load config file specified in ENV '%s' variable. will try to load from standard paths: %s", configFileEnvVar, err)
			loadStandardPaths = true
		}
	} else {
		log.Infof("ENV '%s' variable not set, will try to load from standard paths", configFileEnvVar)
	}

	if loadStandardPaths {
		conf, err = readConfig[E]("/etc/lamassuiot/config.yml", defaults)
	}
	if err != nil {
		return nil, err
	}

	return conf, nil
}
