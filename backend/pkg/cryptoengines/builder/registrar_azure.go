//go:build !noazure

package builder

import (
	"github.com/lamassuiot/lamassuiot/v4/engines/crypto/azure"
	azure_subsystem "github.com/lamassuiot/lamassuiot/v4/engines/crypto/azure/subsystem"
)

func init() {
	azure.RegisterAzureKeyVault()
	azure.RegisterAzureSecrets()
	azure_subsystem.Register()
}
