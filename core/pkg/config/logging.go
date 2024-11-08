package config

type LogLevel string

const (
	Info  LogLevel = "info"
	Debug LogLevel = "debug"
	Trace LogLevel = "trace"
	None  LogLevel = "none"
)

type Logging struct {
	Level LogLevel `mapstructure:"level"`
}
