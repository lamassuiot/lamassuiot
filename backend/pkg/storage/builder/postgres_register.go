package builder

import (
	postgres "github.com/lamassuiot/lamassuiot/v3/storage/postgres"
)

func init() {
	postgres.Register()
}
