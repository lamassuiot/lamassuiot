package main

import (
	"github.com/lamassuiot/lamassuiot/v3/engines/crypto/vaultkv2/subsystem"
	"github.com/lamassuiot/lamassuiot/v3/engines/crypto/vaultkv2/vaultkv2"
)

func init() {
	vaultkv2.Register()
	subsystem.Register()
}
