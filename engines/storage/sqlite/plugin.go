package main

import (
	"github.com/lamassuiot/lamassuiot/v3/engines/storage/sqlite/sqlite"
)

func init() {
	sqlite.Register()
}
