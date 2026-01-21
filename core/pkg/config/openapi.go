package config

type OpenAPIConfig struct {
	Enabled      bool   `mapstructure:"enabled"`
	SpecFilePath string `mapstructure:"spec_file_path"`
}
