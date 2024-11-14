//go:build couchdb
// +build couchdb

package builder

import (
	couchdb "github.com/lamassuiot/lamassuiot/v3/engines/storage/couchdb"
)

func init() {
	couchdb.Register()
}
