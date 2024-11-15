package builder

import (
	"fmt"

	cconfig "github.com/lamassuiot/lamassuiot/v3/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v3/core/pkg/engines/cryptoengines"
	log "github.com/sirupsen/logrus"

	"github.com/lamassuiot/lamassuiot/v3/engines/crypto/aws"
	aws_subsystem "github.com/lamassuiot/lamassuiot/v3/engines/crypto/aws/subsystem"
	"github.com/lamassuiot/lamassuiot/v3/engines/crypto/filesystem"
	"github.com/lamassuiot/lamassuiot/v3/engines/crypto/pkcs11"
	pkcs11_subsystem "github.com/lamassuiot/lamassuiot/v3/engines/crypto/pkcs11/subsystem"
	"github.com/lamassuiot/lamassuiot/v3/engines/crypto/vaultkv2"
	vault_subsystem "github.com/lamassuiot/lamassuiot/v3/engines/crypto/vaultkv2/subsystem"
)

func BuildCryptoEngine(logger *log.Entry, conf cconfig.CryptoEngine) (cryptoengines.CryptoEngine, error) {

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
