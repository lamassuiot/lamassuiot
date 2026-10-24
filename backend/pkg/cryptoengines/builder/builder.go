package builder

import (
	"fmt"

	cconfig "github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/cryptoengines"
	log "github.com/sirupsen/logrus"

	"github.com/lamassuiot/lamassuiot/v4/engines/crypto/filesystem"
)

func BuildCryptoEngine(logger *log.Entry, conf cconfig.CryptoEngineConfig) (cryptoengines.CryptoEngine, error) {
	builder := cryptoengines.GetEngineBuilder(cconfig.CryptoEngineProvider(conf.Type))
	if builder == nil {
		return nil, fmt.Errorf("no crypto engine of type %s", conf.Type)
	}
	return builder(logger, conf)
}

func init() {
	log.Info("Registering default crypto engine")
	filesystem.Register()
}
