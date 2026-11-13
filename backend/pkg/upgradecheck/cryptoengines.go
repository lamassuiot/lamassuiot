package upgradecheck

import (
	"context"
	"fmt"

	bconfig "github.com/lamassuiot/lamassuiot/v4/backend/pkg/config"
	cebuilder "github.com/lamassuiot/lamassuiot/v4/backend/pkg/cryptoengines/builder"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/cryptoengines"
	"github.com/sirupsen/logrus"
)

// CryptoEnginesCheck starts every configured crypto engine and puts the ones that start in env.Engines, for later
// checks. Unlike the KMS, which skips an engine that cannot start, it reports it. Starting an engine may have the
// same side effects as in the KMS (unsealing Vault, creating its KV2 mount or the filesystem directory), but it
// never creates, changes or deletes a key.
func CryptoEnginesCheck(logger *logrus.Entry, conf bconfig.CryptoEngines) Check {
	return Check{
		Name: "crypto engines",
		Run: func(_ context.Context, env *Env) ([]string, error) {
			problems := []string{}
			if env.Engines == nil {
				env.Engines = map[string]cryptoengines.CryptoEngine{}
			}
			for _, cfg := range conf.CryptoEngines {
				engine, err := cebuilder.BuildCryptoEngine(logger, cfg)
				if err != nil {
					problems = append(problems, fmt.Sprintf("crypto engine %s (%s) cannot start: %s", cfg.ID, cfg.Type, err))
					continue
				}
				env.Engines[cfg.ID] = engine
			}
			return problems, nil
		},
	}
}
