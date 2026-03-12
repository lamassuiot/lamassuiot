//go:build !nopkcs11

package builder

import (
	"github.com/lamassuiot/lamassuiot/engines/crypto/pkcs11/v3"
	pkcs11_subsystem "github.com/lamassuiot/lamassuiot/engines/crypto/pkcs11/v3/subsystem"
	log "github.com/sirupsen/logrus"
)

func init() {
	log.Debug("registering PKCS11 crypto engine provider")
	pkcs11.Register()
	pkcs11_subsystem.Register()
}
