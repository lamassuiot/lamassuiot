package config

type AlertsConfig struct {
	BaseConfig `mapstructure:",squash"`
	Storage    PluggableStorageEngine `mapstructure:"storage"`
	SMTPConfig SMTPServer             `mapstructure:"smtp_server"`
}

type SMTPServer struct {
	From     string `json:"from"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	SSL      bool   `json:"ssl"`
	Insecure bool   `json:"insecure"`
}
