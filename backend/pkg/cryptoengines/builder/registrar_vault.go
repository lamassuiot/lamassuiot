//go:build !novault

package builder

import (
	"github.com/lamassuiot/lamassuiot/v4/engines/crypto/vaultkv2"
	vault_subsystem "github.com/lamassuiot/lamassuiot/v4/engines/crypto/vaultkv2/subsystem"
)

func init() {
	vaultkv2.Register()
	vault_subsystem.Register()
}
