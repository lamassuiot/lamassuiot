package main

import (
	"github.com/lamassuiot/lamassuiot/engines/crypto/pkcs11/v3/pkcs11"
	"github.com/lamassuiot/lamassuiot/engines/crypto/pkcs11/v3/subsystem"
)

func init() {
	pkcs11.Register()
	subsystem.Register()
}
