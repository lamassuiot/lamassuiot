package builder

import (
	"fmt"

	cconfig "github.com/lamassuiot/lamassuiot/v2/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/core/pkg/engines/cryptoengines"
	"github.com/lamassuiot/lamassuiot/v2/crypto/vault/pkg/cryptoengines/vaultkv2"
	log "github.com/sirupsen/logrus"

	"github.com/lamassuiot/lamassuiot/v2/crypto/aws/pkg/cryptoengines/aws"
	"github.com/lamassuiot/lamassuiot/v2/pkg/cryptoengines/filesystem"
	pkcs11 "github.com/lamassuiot/lamassuiot/v2/pkg/cryptoengines/pkcs11"
	//"github.com/lamassuiot/lamassuiot/v2/pkg/cryptoengines/vaultkv2"
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
