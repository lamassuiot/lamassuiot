package builder

import (
	authzgorm "github.com/lamassuiot/authz/sdk/gorm"
	postgres "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3"
	subsystem "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3/subsystem"
)

func init() {
	postgres.RegisterGORMPlugin(authzgorm.NewAuthzGormPlugin())
	postgres.Register()
	subsystem.Register()
}
