package builder

import (
	"fmt"

	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines"
	"github.com/lamassuiot/lamassuiot/engines/crypto/aws/v3"
	aws_subsystem "github.com/lamassuiot/lamassuiot/engines/crypto/aws/v3/subsystem"
	"github.com/lamassuiot/lamassuiot/engines/crypto/filesystem/v3"
	"github.com/lamassuiot/lamassuiot/engines/crypto/pkcs11/v3"
	pkcs11_subsystem "github.com/lamassuiot/lamassuiot/engines/crypto/pkcs11/v3/subsystem"
	"github.com/lamassuiot/lamassuiot/engines/crypto/vaultkv2/v3"
	vault_subsystem "github.com/lamassuiot/lamassuiot/engines/crypto/vaultkv2/v3/subsystem"
	log "github.com/sirupsen/logrus"
)

func BuildCryptoEngine(logger *log.Entry, conf cconfig.CryptoEngineConfig) (cryptoengines.CryptoEngine, error) {
	builder := cryptoengines.GetEngineBuilder(cconfig.CryptoEngineProvider(conf.Type))
	if builder == nil {
		return nil, fmt.Errorf("no crypto engine of type %s", conf.Type)
	}
	return builder(logger, conf)
}

func init() {
	log.Info("Registering crypto engines")
	filesystem.Register()

	aws.RegisterAWSKMS()
	aws.RegisterAWSSecrets()
	aws_subsystem.Register()

	vaultkv2.Register()
	vault_subsystem.Register()

	pkcs11.Register()
	pkcs11_subsystem.Register()
}
