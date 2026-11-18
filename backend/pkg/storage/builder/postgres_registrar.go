package builder

import (
	authzgorm "github.com/lamassuiot/lamassuiot/v4/connectors/authz/sdk/gorm"
	postgres "github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres"
	subsystem "github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres/subsystem"
)

func init() {
	postgres.RegisterGORMPlugin(authzgorm.NewAuthzGormPlugin())
	postgres.Register()
	subsystem.Register()
}
