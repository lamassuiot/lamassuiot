package config

type PluggableStorageEngine struct {
	LogLevel LogLevel `mapstructure:"log_level"`

	Provider StorageProvider        `mapstructure:"provider"`
	Config   map[string]interface{} `mapstructure:"config,remain"`
}

type StorageProvider string

const (
	Postgres StorageProvider = "postgres"
	CouchDB  StorageProvider = "couch_db"
	DynamoDB StorageProvider = "dynamo_db"
	SQLite   StorageProvider = "sqlite"
)
