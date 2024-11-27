package main

import (
	"github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3/postgres"
	"github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3/subsystem"
)

func init() {
	postgres.Register()
	subsystem.Register()
}
