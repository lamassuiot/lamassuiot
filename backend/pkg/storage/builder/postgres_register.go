package builder

import (
	postgres "github.com/lamassuiot/lamassuiot/v3/engines/storage/postgres"
	subsystem "github.com/lamassuiot/lamassuiot/v3/engines/storage/postgres/subsystem"
)

func init() {
	postgres.Register()
	subsystem.Register()
}
