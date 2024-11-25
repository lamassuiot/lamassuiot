package main

import (
	"github.com/lamassuiot/lamassuiot/v3/engines/storage/postgres/postgres"
	"github.com/lamassuiot/lamassuiot/v3/engines/storage/postgres/subsystem"
)

func init() {
	postgres.Register()
	subsystem.Register()
}
