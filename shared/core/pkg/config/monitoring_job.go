package config

type MonitoringJob struct {
	Enabled   bool   `mapstructure:"enabled"`
	Frequency string `mapstructure:"frequency"`
}
