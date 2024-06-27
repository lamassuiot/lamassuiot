package assemblers

import (
	"fmt"

	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/cryptoengines"
	"github.com/lamassuiot/lamassuiot/v2/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/pkg/routes"
	"github.com/lamassuiot/lamassuiot/v2/pkg/services"
	"github.com/lamassuiot/lamassuiot/v2/pkg/x509engines"
	log "github.com/sirupsen/logrus"
)

func AssembleKMSServiceWithHTTPServer(conf config.KMSConfig, serviceInfo models.APIServiceInfo) (*services.KMSService, int, error) {
	kmsService, err := AssembleKMSService(conf)
	if err != nil {
		return nil, -1, fmt.Errorf("could not assemble KMS Service. Exiting: %s", err)
	}

	lHttp := helpers.SetupLogger(conf.Server.LogLevel, "KMS", "HTTP Server")

	httpEngine := routes.NewGinEngine(lHttp)
	httpGrp := httpEngine.Group("/")
	routes.NewKMSHTTPLayer(httpGrp, *kmsService)
	port, err := routes.RunHttpRouter(lHttp, httpEngine, conf.Server, serviceInfo)
	if err != nil {
		return nil, -1, fmt.Errorf("could not run KMS Service http server: %s", err)
	}

	return kmsService, port, nil
}

func AssembleKMSService(conf config.KMSConfig) (*services.KMSService, error) {
	lSvc := helpers.SetupLogger(conf.Logs.Level, "KMS", "Service")
	// lMessage := helpers.ConfigureLogger(conf.EventBus.LogLevel, "Event Bus")

	engines, err := createCryptoEngines(lSvc, conf)
	if err != nil {
		return nil, fmt.Errorf("could not create crypto engines: %s", err)
	}

	for engineID, engine := range engines {
		lSvc.WithField("subsystem-provider", "Default Engine").Infof("loaded %s engine with id %s", engine.Service.GetEngineConfig().Type, engineID)
	}

	svc, err := services.NewKMSService(services.KMSServiceBuilder{
		Logger:        lSvc,
		CryptoEngines: engines,
	})
	if err != nil {
		return nil, fmt.Errorf("could not create KMS service: %v", err)
	}

	return &svc, nil
}

func createCryptoEngines(logger *log.Entry, conf config.KMSConfig) (map[string]*services.Engine, error) {
	x509engines.SetCryptoEngineLogger(logger) //Important!

	engines := map[string]*services.Engine{}
	for _, cfg := range conf.CryptoEngines.HashicorpVaultKV2Provider {
		vaultEngine, err := cryptoengines.NewVaultKV2Engine(logger, cfg)
		if err != nil {
			log.Warnf("skipping Hashicorp Vault KV2 engine with id %s. could not create Vault engine: %s", cfg.ID, err)
		} else {
			engines[cfg.ID] = &services.Engine{
				Default: cfg.ID == conf.CryptoEngines.DefaultEngine,
				Service: vaultEngine,
			}
		}
	}

	for _, cfg := range conf.CryptoEngines.AWSKMSProvider {
		awsCfg, err := config.GetAwsSdkConfig(cfg.AWSSDKConfig)
		if err != nil {
			log.Warnf("skipping AWS KMS engine with id %s: %s", cfg.ID, err)
			continue
		}

		awsEngine, err := cryptoengines.NewAWSKMSEngine(logger, *awsCfg, cfg.Metadata)
		if err != nil {
			log.Warnf("skipping AWS KMS engine with id %s. could not create KMS engine: %s", cfg.ID, err)
			continue
		} else {
			engines[cfg.ID] = &services.Engine{
				Default: cfg.ID == conf.CryptoEngines.DefaultEngine,
				Service: awsEngine,
			}
		}
	}

	for _, cfg := range conf.CryptoEngines.AWSSecretsManagerProvider {
		awsCfg, err := config.GetAwsSdkConfig(cfg.AWSSDKConfig)
		if err != nil {
			log.Warnf("skipping AWS Secrets Manager engine with id %s: %s", cfg.ID, err)
			continue
		}

		awsEngine, err := cryptoengines.NewAWSSecretManagerEngine(logger, *awsCfg, cfg.Metadata)
		if err != nil {
			log.Warnf("skipping AWS Secrets Manager with id %s. could not create Secrets Manager engine: %s", cfg.ID, err)
			continue
		} else {
			engines[cfg.ID] = &services.Engine{
				Default: cfg.ID == conf.CryptoEngines.DefaultEngine,
				Service: awsEngine,
			}
		}
	}

	for _, cfg := range conf.CryptoEngines.GolangProvider {
		engine := cryptoengines.NewGolangPEMEngine(logger, cfg)
		engines[cfg.ID] = &services.Engine{
			Default: cfg.ID == conf.CryptoEngines.DefaultEngine,
			Service: engine,
		}
	}

	for _, cfg := range conf.CryptoEngines.PKCS11Provider {
		engine, err := cryptoengines.NewPKCS11Engine(logger, cfg)
		if err != nil {
			log.Warnf("skipping PKCS11 provider with id %s. could not create PKCS11 engine: %s", cfg.ID, err)
		} else {
			engines[cfg.ID] = &services.Engine{
				Default: cfg.ID == conf.CryptoEngines.DefaultEngine,
				Service: engine,
			}
		}
	}

	return engines, nil
}
