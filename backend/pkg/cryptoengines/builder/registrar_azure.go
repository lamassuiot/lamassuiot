//go:build !noazure

package builder

import (
	"github.com/lamassuiot/lamassuiot/engines/crypto/azure/v3"
	azure_subsystem "github.com/lamassuiot/lamassuiot/engines/crypto/azure/v3/subsystem"
	log "github.com/sirupsen/logrus"
)

func init() {
	log.Info("Registering Azure crypto engines")
	azure.RegisterAzureKeyVault()
	azure.RegisterAzureSecrets()
	azure_subsystem.Register()
}
