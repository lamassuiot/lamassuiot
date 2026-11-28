package builder

import (
	authzgorm "github.com/lamassuiot/lamassuiot/v4/connectors/authz/sdk/gorm"
	"github.com/lamassuiot/lamassuiot/v4/engines/storage/oracle"
	oraclesubsystem "github.com/lamassuiot/lamassuiot/v4/engines/storage/oracle/subsystem"
)

func init() {
	oracle.RegisterGORMPlugin(authzgorm.NewOracleAuthzGormPlugin())
	oracle.Register()
	oraclesubsystem.Register()
}
