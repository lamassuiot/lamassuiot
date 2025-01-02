package migrations

import (
	"github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3/migrations/dmsmanager"
)

// the order of the migrations is NOT IMPORTANT. It is only necessary to register them all
func RegisterGoMigrations(dbname string) {
	switch dbname {
	case "dmsmanager":
		dmsmanager.Register_20241230124809_serverkeygen_revokereenroll()
	}
}
