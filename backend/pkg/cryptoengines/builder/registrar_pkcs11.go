//go:build !nopkcs11

package builder

import (
	"github.com/lamassuiot/lamassuiot/v4/engines/crypto/pkcs11"
	pkcs11_subsystem "github.com/lamassuiot/lamassuiot/v4/engines/crypto/pkcs11/subsystem"
	log "github.com/sirupsen/logrus"
)

func init() {
	log.Info("Registering PKCS11 crypto engine")
	pkcs11.Register()
	pkcs11_subsystem.Register()
}
