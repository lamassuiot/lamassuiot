package config

type LogLevel string

const (
	Info  LogLevel = "info"
	Debug LogLevel = "debug"
	Trace LogLevel = "trace"
	None  LogLevel = "none"
)

type LogFormat string

const (
	// LogFormatText renders human-readable, nested text logs (default).
	LogFormatText LogFormat = "text"
	// LogFormatJSON renders structured JSON logs.
	LogFormatJSON LogFormat = "json"
)

type Logging struct {
	Level  LogLevel  `mapstructure:"level"`
	Format LogFormat `mapstructure:"format"`
}
