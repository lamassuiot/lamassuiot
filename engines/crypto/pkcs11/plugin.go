package main

import (
	"github.com/lamassuiot/lamassuiot/v3/engines/crypto/pkcs11/pkcs11"
	"github.com/lamassuiot/lamassuiot/v3/engines/crypto/pkcs11/subsystem"
)

func init() {
	pkcs11.Register()
	subsystem.Register()
}
