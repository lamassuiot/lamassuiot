//go:build couchdb
// +build couchdb

package builder

import (
	couchdb "github.com/lamassuiot/lamassuiot/v2/storage/couchdb"
)

func init() {
	couchdb.Register()
}
