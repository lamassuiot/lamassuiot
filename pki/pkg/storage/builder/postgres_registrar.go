package builder

import (
	authzgorm "github.com/lamassuiot/lamassuiot/connectors/authz/v3/sdk/gorm"
	postgres "github.com/lamassuiot/lamassuiot/pki/v3/engines/storage/postgres"
	subsystem "github.com/lamassuiot/lamassuiot/pki/v3/engines/storage/postgres/subsystem"
)

func init() {
	postgres.RegisterGORMPlugin(authzgorm.NewAuthzGormPlugin())
	postgres.Register()
	subsystem.Register()
}
