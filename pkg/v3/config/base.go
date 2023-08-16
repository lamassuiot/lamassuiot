package config

import (
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type BaseConfig struct {
	// Defines logging options
	Logs struct {
		// General log level to be used. Individual subsystems can be controlled and will override this option. Valid options are `info`, `debug`, `trace`
		Level LogLevel `mapstructure:"level"`
		// Select if health requests should be logged.
		SubsystemLogging struct {
			Service         LogLevel `mapstructure:"service"`
			CryptoEngine    LogLevel `mapstructure:"crypto_engine"`
			StorageEngine   LogLevel `mapstructure:"storage_engine"`
			HttpTransport   LogLevel `mapstructure:"http"`
			MessagingEngine LogLevel `mapstructure:"messaging_engine"`
		} `mapstructure:"subsystems"`
	} `mapstructure:"logs"`

	// Http server configuration options
	Server HttpServer `mapstructure:"server"`

	// AMQP config options.
	AMQPConnection AMQPConnection `mapstructure:"amqp_event_publisher"`
}

type HttpServer struct {
	DebugMode          bool         `mapstructure:"debug_mode"`
	HealthCheckLogging bool         `mapstructure:"health_check"`
	ListenAddress      string       `mapstructure:"listen_address"`
	Port               int          `mapstructure:"port"`
	Protocol           HTTPProtocol `mapstructure:"protocol"`
	CertFile           string       `mapstructure:"cert_file"`
	KeyFile            string       `mapstructure:"key_file"`
	Authentication     struct {
		MutualTLS struct {
			Enabled           bool          `mapstructure:"enabled"`
			ValidationMode    MutualTLSMode `mapstructure:"validation_mode"`
			CACertificateFile string        `mapstructure:"ca_cert_file"`
		} `mapstructure:"mutual_tls"`
	} `mapstructure:"authentication"`
}

type MutualTLSMode string

const (
	Strict  MutualTLSMode = "strict"
	Request MutualTLSMode = "request"
	Any     MutualTLSMode = "any"
)

type PluggableStorageEngine struct {
	Provider StorageProvider `mapstructure:"provider"`

	CouchDB  CouchDBPSEConfig  `mapstructure:"couch_db"`
	Postgres PostgresPSEConfig `mapstructure:"postgres"`
}

type CouchDBPSEConfig struct {
	HTTPConnection `mapstructure:",squash"`
	Username       string `mapstructure:"username"`
	Password       string `mapstructure:"password"`
}

type PostgresPSEConfig struct {
	Hostname string `mapstructure:"hostname"`
	Port     int    `mapstructure:"port"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
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
	Enabled         bool                    `mapstructure:"enabled"`
	Protocol        AMQPProtocol            `mapstructure:"protocol"`
	BasicAuth       AMQPConnectionBasicAuth `mapstructure:"basic_auth"`
	ClientTLSAuth   struct {
		Enabled  bool   `mapstructure:"enabled"`
		CertFile string `mapstructure:"cert_file"`
		KeyFile  string `mapstructure:"key_file"`
	} `mapstructure:"client_tls_auth"`
}
type AMQPConnectionBasicAuth struct {
	Enabled  bool   `mapstructure:"enabled"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
}

type HTTPClient struct {
	AuthMode        HTTPClientAuthMethod `mapstructure:"auth_mode"`
	AuthJWTOptions  AuthJWTOptions       `mapstructure:"jwt_options"`
	AuthMTLSOptions AuthMTLSOptions      `mapstructure:"mtls_options"`
	Level           LogLevel             `mapstructure:"level"`
	HTTPConnection  `mapstructure:",squash"`
}

type AuthJWTOptions struct {
	ClientID         string `mapstructure:"oidc_client_id"`
	ClientSecret     string `mapstructure:"oidc_client_secret"`
	OIDCWellKnownURL string `mapstructure:"oidc_well_known"`
}

type AuthMTLSOptions struct {
	CertFile string `mapstructure:"cert_file"`
	KeyFile  string `mapstructure:"key_file"`
}

func readConfig[E any](configFilePath string) (*E, error) {
	vp := viper.New()
	vp.SetConfigFile(configFilePath)

	if err := vp.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found; ignore error if desired
			return nil, fmt.Errorf("config file not found: %s", err)
		} else {
			// Config file was found but another error was produced
			return nil, fmt.Errorf("error while procesing config file: %w", err)
		}
	}

	var config E
	err := vp.Unmarshal(&config)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal config: %w", err)
	}

	return &config, nil
}

func LoadConfig[E any]() (*E, error) {
	var err error
	var conf *E

	configFileEnvVar := "LAMASSU_CONFIG_FILE"
	configFileEnv := os.Getenv(configFileEnvVar)
	loadStandardPaths := true

	if configFileEnv != "" {
		loadStandardPaths = false
		log.Infof("loading config file from %s", configFileEnv)
		conf, err = readConfig[E](configFileEnv)

		if err != nil {
			log.Warnf("failed to load config file specified in ENV '%s' variable. will try to load from standard paths: %s", configFileEnvVar, err)
			loadStandardPaths = true
		}
	} else {
		log.Infof("ENV '%s' variable not set, will try to load from standard paths", configFileEnvVar)
	}

	if loadStandardPaths {
		conf, err = readConfig[E]("/etc/lamassuiot/config.yml")
	}
	if err != nil {
		return nil, err
	}

	return conf, nil
}
