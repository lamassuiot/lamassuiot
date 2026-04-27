package main

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"os"
	"time"

	storagebuilder "github.com/lamassuiot/lamassuiot/backend/v3/pkg/storage/builder"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	log "github.com/sirupsen/logrus"
)

// MigrationConfig holds the storage configurations for both the CA and KMS databases.
type MigrationConfig struct {
	LogLevel   cconfig.LogLevel               `mapstructure:"log_level"`
	CAStorage  cconfig.PluggableStorageEngine `mapstructure:"ca_storage"`
	KMSStorage cconfig.PluggableStorageEngine `mapstructure:"kms_storage"`
}

func main() {
	dryRun := flag.Bool("dry-run", false, "scan and report without writing to KMS storage")
	flag.Parse()

	log.SetFormatter(helpers.LogFormatter)

	conf, err := cconfig.LoadConfig[MigrationConfig](nil)
	if err != nil {
		log.Fatalf("could not load config: %s", err)
	}

	lvl, err := log.ParseLevel(string(conf.LogLevel))
	if err != nil {
		log.Warn("unknown log level; defaulting to 'info'")
		lvl = log.InfoLevel
	}
	log.SetLevel(lvl)

	logger := helpers.SetupLogger(conf.LogLevel, "Migration", "ca-to-kms")
	if *dryRun {
		logger.Info("running in dry-run mode — no writes will occur")
	}

	ctx := context.Background()

	// Build CA storage (read-only access required).
	caEngine, err := storagebuilder.BuildStorageEngine(logger.WithField("db", "ca"), conf.CAStorage)
	if err != nil {
		log.Fatalf("could not build CA storage engine: %s", err)
	}
	caStorage, err := caEngine.GetCAStorage()
	if err != nil {
		log.Fatalf("could not get CA storage: %s", err)
	}

	// Build KMS storage (read / write).
	kmsEngine, err := storagebuilder.BuildStorageEngine(logger.WithField("db", "kms"), conf.KMSStorage)
	if err != nil {
		log.Fatalf("could not build KMS storage engine: %s", err)
	}
	kmsStorage, err := kmsEngine.GetKMSStorage()
	if err != nil {
		log.Fatalf("could not get KMS storage: %s", err)
	}

	keyMap := collectKeys(ctx, logger, caStorage)
	logger.Infof("found %d unique keys across CA certificates", len(keyMap))

	runMigration(ctx, logger, kmsStorage, keyMap, *dryRun)
}

// keyEntry accumulates all data needed to build a models.Key record.
type keyEntry struct {
	engineID   string
	keyID      string // subject_key_id == KMS key_id (SHA-256 hex of PKIX public key)
	algorithm  string
	size       int
	publicKey  string // base64(PEM "PUBLIC KEY")
	name       string // common name of first CA cert using this key
	creationTS time.Time
	serials    []string // serial numbers of all CA certs using this key
}

// collectKeys scans MANAGED and IMPORTED_WITH_KEY CA certs and groups them by key.
func collectKeys(ctx context.Context, logger *log.Entry, caStorage storage.CACertificatesRepo) map[string]*keyEntry {
	keyMap := map[string]*keyEntry{}

	collect := func(ca models.CACertificate) {
		cert := ca.Certificate
		if cert.EngineID == "" || cert.SubjectKeyID == "" {
			logger.Warnf("skipping CA %s: missing engine_id or subject_key_id", ca.ID)
			return
		}
		if cert.Certificate == nil {
			logger.Warnf("skipping CA %s: nil certificate blob", ca.ID)
			return
		}

		x509Cert := (*x509.Certificate)(cert.Certificate)
		pubKeyDER, err := x509.MarshalPKIXPublicKey(x509Cert.PublicKey)
		if err != nil {
			logger.Errorf("could not marshal public key for CA %s: %s", ca.ID, err)
			return
		}
		pubKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyDER})
		pubKeyB64 := base64.StdEncoding.EncodeToString(pubKeyPEM)

		keyID := cert.SubjectKeyID
		if entry, ok := keyMap[keyID]; ok {
			entry.serials = append(entry.serials, cert.SerialNumber)
		} else {
			keyMap[keyID] = &keyEntry{
				engineID:   cert.EngineID,
				keyID:      keyID,
				algorithm:  cert.KeyMetadata.Type.String(),
				size:       cert.KeyMetadata.Bits,
				publicKey:  pubKeyB64,
				name:       cert.Subject.CommonName,
				creationTS: cert.ValidFrom,
				serials:    []string{cert.SerialNumber},
			}
		}
	}

	for _, certType := range []models.CertificateType{
		models.CertificateTypeManaged,
		models.CertificateTypeImportedWithKey,
	} {
		_, err := caStorage.SelectByType(ctx, certType, storage.StorageListRequest[models.CACertificate]{
			ExhaustiveRun: true,
			ApplyFunc:     collect,
		})
		if err != nil {
			log.Fatalf("could not list CA certs of type %s: %s", certType, err)
		}
	}

	return keyMap
}

// runMigration inserts missing keys into KMS storage (or logs what it would do in dry-run mode).
func runMigration(ctx context.Context, logger *log.Entry, kmsStorage storage.KMSKeysRepo, keyMap map[string]*keyEntry, dryRun bool) {
	inserted, skipped, failed := 0, 0, 0

	for _, entry := range keyMap {
		exists, _, err := kmsStorage.SelectExistsByKeyID(ctx, entry.keyID)
		if err != nil {
			logger.Errorf("could not check key %s in KMS storage: %s", entry.keyID, err)
			failed++
			continue
		}
		if exists {
			logger.Debugf("key %s already in KMS storage — skipping", entry.keyID)
			skipped++
			continue
		}

		bindedResources := make([]models.KMSBindResource, len(entry.serials))
		for i, sn := range entry.serials {
			bindedResources[i] = models.KMSBindResource{
				ResourceType: "certificate",
				ResourceID:   sn,
			}
		}

		key := &models.Key{
			KeyID:         entry.keyID,
			EngineID:      entry.engineID,
			Name:          entry.name,
			Aliases:       []string{},
			HasPrivateKey: true,
			Algorithm:     entry.algorithm,
			Size:          entry.size,
			PublicKey:     entry.publicKey,
			CreationTS:    entry.creationTS,
			Tags:          []string{},
			Metadata: map[string]any{
				models.KMSBindResourceKey: bindedResources,
			},
		}

		logger.Infof("key %s — engine=%s alg=%s bits=%d binds=%d",
			entry.keyID, entry.engineID, entry.algorithm, entry.size, len(entry.serials))

		if dryRun {
			inserted++ // count as "would insert"
			continue
		}

		if _, err = kmsStorage.Insert(ctx, key); err != nil {
			logger.Errorf("could not insert key %s: %s", entry.keyID, err)
			failed++
			continue
		}
		inserted++
	}

	action := "inserted"
	if dryRun {
		action = "would insert"
	}
	logger.Infof("migration complete: %s=%d skipped=%d failed=%d", action, inserted, skipped, failed)

	if failed > 0 {
		os.Exit(1)
	}
}
