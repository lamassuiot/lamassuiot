package config

type OTELConfig struct {
	Metrics OTELMetricsConfig `mapstructure:"metrics"`
	Traces  OTELTracesConfig  `mapstructure:"traces"`
	Logging OTELLoggingConfig `mapstructure:"logging"`
}

type OTELMetricsConfig struct {
	Enabled          bool   `mapstructure:"enabled"`
	IntervalInMillis int    `mapstructure:"interval_in_millis"`
	Hostname         string `mapstructure:"hostname"`
	Port             int    `mapstructure:"port"`
	Scheme           string `mapstructure:"scheme"`
}

type OTELTracesConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	Hostname string `mapstructure:"hostname"`
	Port     int    `mapstructure:"port"`
	Scheme   string `mapstructure:"scheme"`
}

type OTELLoggingConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	Hostname string `mapstructure:"hostname"`
	Port     int    `mapstructure:"port"`
	Scheme   string `mapstructure:"scheme"`
}
