package main

import (
	"github.com/lamassuiot/lamassuiot/engines/crypto/vaultkv2/v3/subsystem"
	"github.com/lamassuiot/lamassuiot/engines/crypto/vaultkv2/v3/vaultkv2"
)

func init() {
	vaultkv2.Register()
	subsystem.Register()
}
