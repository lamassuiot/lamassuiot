package main

import (
	"github.com/lamassuiot/lamassuiot/v3/engines/storage/couchdb/couchdb"
	"github.com/lamassuiot/lamassuiot/v3/engines/storage/couchdb/subsystem"
)

func init() {
	couchdb.Register()
	subsystem.Register()
}
