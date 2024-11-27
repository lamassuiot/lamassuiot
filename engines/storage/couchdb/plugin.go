package main

import (
	"github.com/lamassuiot/lamassuiot/engines/storage/couchdb/v3/couchdb"
	"github.com/lamassuiot/lamassuiot/engines/storage/couchdb/v3/subsystem"
)

func init() {
	couchdb.Register()
	subsystem.Register()
}
