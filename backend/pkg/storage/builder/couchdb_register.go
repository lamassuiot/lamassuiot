//go:build couchdb
// +build couchdb

package builder

import (
	couchdb "github.com/lamassuiot/lamassuiot/v3/storage/couchdb"
)

func init() {
	couchdb.Register()
}
