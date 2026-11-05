//go:build !nopkcs11

package builder

import (
	"github.com/lamassuiot/lamassuiot/v4/engines/crypto/pkcs11"
	pkcs11_subsystem "github.com/lamassuiot/lamassuiot/v4/engines/crypto/pkcs11/subsystem"
)

func init() {
	pkcs11.Register()
	pkcs11_subsystem.Register()
}
