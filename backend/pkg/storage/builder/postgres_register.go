package builder

import (
	postgres "github.com/lamassuiot/lamassuiot/v3/engines/storage/postgres"
)

func init() {
	postgres.Register()
}
