package builder

import (
	postgres "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3"
	subsystem "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3/subsystem"
)

func init() {
	postgres.Register()
	subsystem.Register()
}
