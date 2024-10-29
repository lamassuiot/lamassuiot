package config

type PluggableStorageEngine struct {
	LogLevel LogLevel `mapstructure:"log_level"`

	Provider StorageProvider `mapstructure:"provider"`

	CouchDB  CouchDBPSEConfig  `mapstructure:"couch_db"`
	Postgres PostgresPSEConfig `mapstructure:"postgres"`
	SQLite   SQLitePSEConfig   `mapstructure:"sqlite"`
}

type CouchDBPSEConfig struct {
	HTTPConnection `mapstructure:",squash"`
	Username       string   `mapstructure:"username"`
	Password       Password `mapstructure:"password"`
}

type SQLitePSEConfig struct {
	DatabasePath string `mapstructure:"database_path"`
	InMemory     bool   `mapstructure:"in_memory"`
}

type PostgresPSEConfig struct {
	Hostname string   `mapstructure:"hostname"`
	Port     int      `mapstructure:"port"`
	Username string   `mapstructure:"username"`
	Password Password `mapstructure:"password"`
}

type StorageProvider string

const (
	Postgres StorageProvider = "postgres"
	CouchDB  StorageProvider = "couch_db"
	DynamoDB StorageProvider = "dynamo_db"
	SQLite   StorageProvider = "sqlite"
)
