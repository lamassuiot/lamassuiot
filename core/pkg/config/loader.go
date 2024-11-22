package config

import (
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
)

func DecodeStruct[E any](source interface{}) (E, error) {
	var target E
	err := mapstructure.Decode(source, &target)
	if err != nil {
		var zero E
		return zero, fmt.Errorf("could not decode struct: %w", err)
	}
	return target, nil
}

func EncodeStruct[E any](source E) (map[string]interface{}, error) {
	var target map[string]interface{}
	err := mapstructure.Decode(source, &target)
	if err != nil {
		return nil, fmt.Errorf("could not decode struct: %w", err)
	}
	return target, nil
}

func readConfig[E any](configFilePath string, defaults *E) (*E, error) {
	vp := viper.New()
	defaultsMap := map[string]interface{}{}

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
