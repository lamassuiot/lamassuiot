package builder

import (
	"fmt"

	cconfig "github.com/lamassuiot/lamassuiot/v3/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v3/core/pkg/engines/cryptoengines"
	log "github.com/sirupsen/logrus"

	"github.com/lamassuiot/lamassuiot/v3/crypto/aws"
	"github.com/lamassuiot/lamassuiot/v3/crypto/filesystem"
	"github.com/lamassuiot/lamassuiot/v3/crypto/pkcs11"
	"github.com/lamassuiot/lamassuiot/v3/crypto/vaultkv2"
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
	vaultkv2.Register()
	pkcs11.Register()
}
