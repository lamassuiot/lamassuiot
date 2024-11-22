//go:build experimental || couchdb

package builder

import (
	couchdb "github.com/lamassuiot/lamassuiot/v3/engines/storage/couchdb"
	subsystem "github.com/lamassuiot/lamassuiot/v3/engines/storage/couchdb/subsystem"
)

func init() {
	couchdb.Register()
	subsystem.Register()
}
