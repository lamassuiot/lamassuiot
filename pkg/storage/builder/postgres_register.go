package builder

import (
	postgres "github.com/lamassuiot/lamassuiot/v2/pkg/storage/postgres"
)

func init() {
	postgres.Register()
}
