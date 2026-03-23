package assemblers

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/config"
	cebuilder "github.com/lamassuiot/lamassuiot/backend/v3/pkg/cryptoengines/builder"
	auditpub "github.com/lamassuiot/lamassuiot/backend/v3/pkg/middlewares/audit"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/middlewares/eventpub"
	otel "github.com/lamassuiot/lamassuiot/backend/v3/pkg/middlewares/otel"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/servicebuilder"
	lservices "github.com/lamassuiot/lamassuiot/backend/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/storage/builder"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/engines/crypto/software/v3"
	sdk "github.com/lamassuiot/lamassuiot/sdk/v3"
	log "github.com/sirupsen/logrus"
)

// RunKMS is the entry point for the standalone KMS service binary.
// It loads config, assembles the full service, and blocks.
func RunKMS(serviceInfo models.APIServiceInfo) {
	servicebuilder.Run[config.KMSConfig](serviceInfo, func(conf config.KMSConfig, info models.APIServiceInfo) error {
		_, _, err := AssembleKMSServiceWithHTTPServer(conf, info)
		return err
	})
}

// AssembleKMSService builds and wires the KMS service: storage, crypto engines, service, and all middlewares.
func AssembleKMSService(conf config.KMSConfig) (services.KMSService, error) {
	sdk.InitOtelSDK(context.Background(), "KMS Service", conf.OtelConfig)

	lSvc := helpers.SetupLogger(conf.Logs.Level, "KMS", "Service")
	lMessage := helpers.SetupLogger(conf.PublisherEventBus.LogLevel, "KMS", "Event Bus")
	lAudit := helpers.SetupLogger(conf.PublisherEventBus.LogLevel, "KMS", "Audit Bus")
	lStorage := helpers.SetupLogger(conf.Storage.LogLevel, "KMS", "Storage")
	lCryptoEng := helpers.SetupLogger(conf.CryptoEngineConfig.LogLevel, "KMS", "CryptoEngine")

	kmsStorage, err := createKMSStorageInstance(lStorage, conf.Storage)
	if err != nil {
		return nil, fmt.Errorf("could not create KMS storage: %s", err)
	}

	engines, err := createCryptoEngines(lCryptoEng, conf)
	if err != nil {
		return nil, fmt.Errorf("could not create crypto engines: %s", err)
	}

	for engineID, engine := range engines {
		logEntry := log.NewEntry(log.StandardLogger())
		if engine.Default {
			logEntry = log.WithField("subsystem-provider", "DEFAULT ENGINE")
		}
		logEntry.Infof("loaded %s engine with id %s", engine.Service.GetEngineConfig().Type, engineID)

		if conf.CryptoEngineConfig.MigrateKeysFormat {
			if err := migrateKeysToV2Format(lSvc, engine, engineID); err != nil {
				return nil, fmt.Errorf("could not migrate %s engine keys to v2 format: %s", engineID, err)
			}
		}
	}

	svc, err := lservices.NewKMSService(lservices.KMSServiceBuilder{
		Logger:        lSvc,
		KMSStorage:    kmsStorage,
		CryptoEngines: engines,
	})
	if err != nil {
		return nil, fmt.Errorf("could not create KMS service: %s", err)
	}

	backend := svc.(*lservices.KMSServiceBackend)
	svc, err = servicebuilder.ApplyMiddlewares(
		"KMS", "kms", conf.PublisherEventBus,
		svc, backend.SetService,
		func(s services.KMSService) services.KMSService { return otel.NewKMSOTelTracer()(s) },
		func(s services.KMSService, p eventpub.ICloudEventPublisher) services.KMSService {
			return eventpub.NewKMSEventBusPublisher(p)(s)
		},
		func(s services.KMSService, a auditpub.AuditPublisher) services.KMSService {
			return auditpub.NewKMSAuditEventBusPublisher(a)(s)
		},
		lMessage, lAudit,
	)
	if err != nil {
		return nil, err
	}

	return svc, nil
}

// AssembleKMSServiceWithHTTPServer assembles the KMS service and starts the HTTP server.
// Returns the service, the bound port, and any error.
func AssembleKMSServiceWithHTTPServer(conf config.KMSConfig, serviceInfo models.APIServiceInfo) (*services.KMSService, int, error) {
	svc, err := AssembleKMSService(conf)
	if err != nil {
		return nil, -1, fmt.Errorf("could not assemble KMS Service: %s", err)
	}

	lHttp := helpers.SetupLogger(conf.Server.LogLevel, "KMS", "HTTP Server")
	httpEngine := routes.NewGinEngine(lHttp)
	routes.NewKMSHTTPLayer(httpEngine.Group("/"), svc)
	port, err := routes.RunHttpRouter(lHttp, httpEngine, conf.Server, serviceInfo)
	if err != nil {
		return nil, -1, fmt.Errorf("could not run KMS HTTP server: %s", err)
	}

	return &svc, port, nil
}

func createKMSStorageInstance(logger *log.Entry, conf cconfig.PluggableStorageEngine) (storage.KMSKeysRepo, error) {
	engine, err := builder.BuildStorageEngine(logger, conf)
	if err != nil {
		return nil, fmt.Errorf("could not create storage engine: %s", err)
	}

	kmsStorage, err := engine.GetKMSStorage()
	if err != nil {
		return nil, fmt.Errorf("could not get KMS storage: %s", err)
	}

	return kmsStorage, nil
}

func createCryptoEngines(logger *log.Entry, conf config.KMSConfig) (map[string]*lservices.Engine, error) {
	engines := map[string]*lservices.Engine{}

	for _, cfg := range conf.CryptoEngineConfig.CryptoEngines {
		engine, err := cebuilder.BuildCryptoEngine(logger, cfg)

		if err != nil {
			log.Warnf("skipping engine with id %s of type %s. Can not create engine: %s", cfg.ID, cfg.Type, err)
		} else {
			engines[cfg.ID] = &lservices.Engine{
				Default: cfg.ID == conf.CryptoEngineConfig.DefaultEngine,
				Service: engine,
			}
		}
	}

	return engines, nil
}

func migrateKeysToV2Format(logger *log.Entry, engine *lservices.Engine, engineID string) error {
	// Check if engine keys should be renamed
	keyIDs, err := engine.Service.ListPrivateKeyIDs()
	if err != nil {
		return nil
	}
	keyMigLog := logger.WithField("engine", engineID)
	softCrypto := software.NewSoftwareCryptoEngine(keyMigLog)
	keyMigLog.Infof("checking engine keys format")

	// Iter over all keys and rename if not in sha256 hex format
	for _, keyID := range keyIDs {
		key, err := engine.Service.GetPrivateKeyByID(keyID)
		if err != nil {
			return fmt.Errorf("could not get key %s: %w", keyID, err)
		}

		newKeyID, err := softCrypto.EncodePKIXPublicKeyDigest(key.Public())
		if err != nil {
			return fmt.Errorf("could not encode public key digest: %w", err)
		}

		// only rename if different
		if newKeyID != keyID {
			keyMigLog.Debugf("renaming key %s to %s", keyID, newKeyID)
			err = engine.Service.RenameKey(keyID, newKeyID)
			if err != nil {
				return fmt.Errorf("could not rename key %s: %w", keyID, err)
			}
		}
	}
	return nil
}

func migrateKeysToV3Format(logger *log.Entry, caCertsRepo storage.CACertificatesRepo, engine *lservices.Engine, engineID string) error {
	mapKeyIDToSha256Hex := map[string]string{}
	keyIDs, err := engine.Service.ListPrivateKeyIDs()
	if err != nil {
		return nil
	}

	keyMigLog := logger.WithField("engine", engineID)
	softCrypto := software.NewSoftwareCryptoEngine(keyMigLog)
	keyMigLog.Infof("checking engine keys format")

	for _, keyID := range keyIDs {
		key, err := engine.Service.GetPrivateKeyByID(keyID)
		if err != nil {
			return fmt.Errorf("could not get key %s: %w", keyID, err)
		}

		shaInHex, err := softCrypto.EncodePKIXPublicKeyDigest(key.Public())
		if err != nil {
			return fmt.Errorf("could not encode public key digest: %w", err)
		}

		mapKeyIDToSha256Hex[shaInHex] = keyID
	}

	// Iterate over all CA certs of type IMPORTED and check if their SKI matches the keyID in the engine
	// If not, rename the key in the engine to match the SKI
	_, err = caCertsRepo.SelectByType(context.Background(), models.CertificateTypeImportedWithKey, storage.StorageListRequest[models.CACertificate]{
		ExhaustiveRun: true,
		ApplyFunc: func(ca models.CACertificate) {
			certSN := ca.Certificate.SerialNumber
			x509 := ca.Certificate.Certificate
			certPubKeySha256Hex, err := softCrypto.EncodePKIXPublicKeyDigest(x509.PublicKey)
			if err != nil {
				keyMigLog.Errorf("could not encode public key digest for cert %s: %s", certSN, err)
				return
			}

			certSkiInHex := hex.EncodeToString(x509.SubjectKeyId)

			if oldKeyID, ok := mapKeyIDToSha256Hex[certPubKeySha256Hex]; ok && certSkiInHex != oldKeyID {
				keyMigLog.Infof("migrating cert %s from keyID %s to %s", certSN, oldKeyID, certSkiInHex)
				err = engine.Service.RenameKey(oldKeyID, certSkiInHex)
				if err != nil {
					keyMigLog.Errorf("could not rename key %s to %s: %s", oldKeyID, certSkiInHex, err)
					return
				}
			}
		},
	})
	if err != nil {
		return fmt.Errorf("could not select all certificates: %w", err)
	}

	return nil
}
