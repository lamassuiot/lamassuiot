//go:build !noazure

package builder

import (
	"github.com/lamassuiot/lamassuiot/v4/engines/crypto/azure"
	azure_subsystem "github.com/lamassuiot/lamassuiot/v4/engines/crypto/azure/subsystem"
	log "github.com/sirupsen/logrus"
)

func init() {
	log.Info("Registering Azure crypto engines")
	azure.RegisterAzureKeyVault()
	azure.RegisterAzureSecrets()
	azure_subsystem.Register()
}
