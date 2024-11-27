package main

import (
	"github.com/lamassuiot/lamassuiot/engines/storage/sqlite/v3/sqlite"
)

func init() {
	sqlite.Register()
}
