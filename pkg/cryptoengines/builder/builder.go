package builder

import (
	"fmt"

	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/cryptoengines"
	log "github.com/sirupsen/logrus"

	"github.com/lamassuiot/lamassuiot/v2/pkg/cryptoengines/aws"
	"github.com/lamassuiot/lamassuiot/v2/pkg/cryptoengines/filesystem"
	pkcs11 "github.com/lamassuiot/lamassuiot/v2/pkg/cryptoengines/pkcs11"
	"github.com/lamassuiot/lamassuiot/v2/pkg/cryptoengines/vaultkv2"
)

func BuildCryptoEngine(logger *log.Entry, conf config.CryptoEngine) (cryptoengines.CryptoEngine, error) {

	builder := cryptoengines.GetEngineBuilder(config.CryptoEngineProvider(conf.Type))
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
