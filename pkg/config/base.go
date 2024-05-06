package config

import (
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type Password string

func (p Password) MarshalText() ([]byte, error) {
	return []byte("*************"), nil
}

func (p *Password) UnmarshalText(text []byte) (err error) {
	pw := string(text)
	p = (*Password)(&pw)
	return nil
}

type BaseConfigLogging struct {
	Level LogLevel `mapstructure:"level"`
}

type HttpServer struct {
	LogLevel           LogLevel                 `mapstructure:"log_level"`
	HealthCheckLogging bool                     `mapstructure:"health_check"`
	ListenAddress      string                   `mapstructure:"listen_address"`
	Port               int                      `mapstructure:"port"`
	Protocol           HTTPProtocol             `mapstructure:"protocol"`
	CertFile           string                   `mapstructure:"cert_file"`
	KeyFile            string                   `mapstructure:"key_file"`
	Authentication     HttpServerAuthentication `mapstructure:"authentication"`
}

type HttpServerAuthentication struct {
	MutualTLS HttpServerMutualTLSAuthentication `mapstructure:"mutual_tls"`
}
type HttpServerMutualTLSAuthentication struct {
	Enabled           bool          `mapstructure:"enabled"`
	ValidationMode    MutualTLSMode `mapstructure:"validation_mode"`
	CACertificateFile string        `mapstructure:"ca_cert_file"`
}

type MutualTLSMode string

const (
	Strict  MutualTLSMode = "strict"
	Request MutualTLSMode = "request"
	Any     MutualTLSMode = "any"
)

type PluggableStorageEngine struct {
	LogLevel LogLevel `mapstructure:"log_level"`

	Provider StorageProvider `mapstructure:"provider"`

	CouchDB  CouchDBPSEConfig  `mapstructure:"couch_db"`
	Postgres PostgresPSEConfig `mapstructure:"postgres"`
}

type CouchDBPSEConfig struct {
	HTTPConnection `mapstructure:",squash"`
	Username       string   `mapstructure:"username"`
	Password       Password `mapstructure:"password"`
}

type PostgresPSEConfig struct {
	Hostname string   `mapstructure:"hostname"`
	Port     int      `mapstructure:"port"`
	Username string   `mapstructure:"username"`
	Password Password `mapstructure:"password"`
}

type EventBusEngine struct {
	LogLevel LogLevel `mapstructure:"log_level"`
	Enabled  bool     `mapstructure:"enabled"`

	Provider EventBusProvider `mapstructure:"provider"`

	Amqp      AMQPConnection `mapstructure:"amqp"`
	AWSSqsSns AWSSDKConfig   `mapstructure:"aws_sqs_sns"`
}

type TLSConfig struct {
	InsecureSkipVerify bool   `mapstructure:"insecure_skip_verify"`
	CACertificateFile  string `mapstructure:"ca_cert_file"`
}

type BasicConnection struct {
	Hostname  string `mapstructure:"hostname"`
	Port      int    `mapstructure:"port"`
	TLSConfig `mapstructure:",squash"`
}

type HTTPConnection struct {
	Protocol        HTTPProtocol `mapstructure:"protocol"`
	BasePath        string       `mapstructure:"base_path"`
	BasicConnection `mapstructure:",squash"`
}

type AMQPConnection struct {
	BasicConnection `mapstructure:",squash"`
	Exchange        string                  `mapstructure:"exchange"`
	Protocol        AMQPProtocol            `mapstructure:"protocol"`
	BasicAuth       AMQPConnectionBasicAuth `mapstructure:"basic_auth"`
	ClientTLSAuth   struct {
		Enabled  bool   `mapstructure:"enabled"`
		CertFile string `mapstructure:"cert_file"`
		KeyFile  string `mapstructure:"key_file"`
	} `mapstructure:"client_tls_auth"`
}
type AMQPConnectionBasicAuth struct {
	Enabled  bool     `mapstructure:"enabled"`
	Username string   `mapstructure:"username"`
	Password Password `mapstructure:"password"`
}

type HTTPClient struct {
	LogLevel        LogLevel             `mapstructure:"log_level"`
	AuthMode        HTTPClientAuthMethod `mapstructure:"auth_mode"`
	AuthJWTOptions  AuthJWTOptions       `mapstructure:"jwt_options"`
	AuthMTLSOptions AuthMTLSOptions      `mapstructure:"mtls_options"`
	HTTPConnection  `mapstructure:",squash"`
}

type AuthJWTOptions struct {
	ClientID         string   `mapstructure:"oidc_client_id"`
	ClientSecret     Password `mapstructure:"oidc_client_secret"`
	OIDCWellKnownURL string   `mapstructure:"oidc_well_known"`
}

type AuthMTLSOptions struct {
	CertFile string `mapstructure:"cert_file"`
	KeyFile  string `mapstructure:"key_file"`
}

func readConfig[E any](configFilePath string, defaults map[string]interface{}) (*E, error) {
	vp := viper.New()
	for key, value := range defaults {
		vp.SetDefault(key, value)
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

	var config E
	err := vp.Unmarshal(&config)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal config: %w", err)
	}

	return &config, nil
}

func LoadConfig[E any](defaults map[string]interface{}) (*E, error) {
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
