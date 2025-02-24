//go:build !novault

package builder

import (
	"github.com/lamassuiot/lamassuiot/engines/crypto/vaultkv2/v3"
	vault_subsystem "github.com/lamassuiot/lamassuiot/engines/crypto/vaultkv2/v3/subsystem"
	log "github.com/sirupsen/logrus"
)

func init() {
	log.Info("Registering VaultKV crypto engines")
	vaultkv2.Register()
	vault_subsystem.Register()
}
