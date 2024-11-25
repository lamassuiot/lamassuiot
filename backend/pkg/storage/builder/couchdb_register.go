//go:build experimental || couchdb

package builder

import (
	couchdb "github.com/lamassuiot/lamassuiot/engines/storage/couchdb/v3"
	subsystem "github.com/lamassuiot/lamassuiot/engines/storage/couchdb/v3/subsystem"
)

func init() {
	couchdb.Register()
	subsystem.Register()
}
