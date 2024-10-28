package config

import (
	"fmt"

	"github.com/go-viper/mapstructure/v2"
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

type HTTPConnection struct {
	Protocol        HTTPProtocol `mapstructure:"protocol"`
	BasePath        string       `mapstructure:"base_path"`
	BasicConnection `mapstructure:",squash"`
}

type HTTPProtocol string

const (
	HTTPS HTTPProtocol = "https"
	HTTP  HTTPProtocol = "http"
)

type BasicConnection struct {
	Hostname  string `mapstructure:"hostname"`
	Port      int    `mapstructure:"port"`
	TLSConfig `mapstructure:",squash"`
}

type TLSConfig struct {
	InsecureSkipVerify bool   `mapstructure:"insecure_skip_verify"`
	CACertificateFile  string `mapstructure:"ca_cert_file"`
}

func DecodeStruct[E any](source map[string]interface{}) (E, error) {

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
