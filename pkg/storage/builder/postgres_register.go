package builder

import (
	postgres "github.com/lamassuiot/lamassuiot/v2/storage/postgres"
)

func init() {
	postgres.Register()
}
