package config

type LogLevel string

const (
	Info  LogLevel = "info"
	Debug LogLevel = "debug"
	Trace LogLevel = "trace"
	None  LogLevel = "none"
)

type AWSAuthenticationMethod string

const (
	Static     AWSAuthenticationMethod = "static"
	Default    AWSAuthenticationMethod = "default"
	AssumeRole AWSAuthenticationMethod = "role"
)
