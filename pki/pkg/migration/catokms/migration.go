package catokms

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"time"

	storagebuilder "github.com/lamassuiot/lamassuiot/pki/v3/pkg/storage/builder"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	log "github.com/sirupsen/logrus"
)

// Result summarises the outcome of a migration run.
type Result struct {
	Inserted int
	Skipped  int
	Failed   int
}

// Migrate runs the migration using pre-built storage instances.
// This is the primary entry point for programmatic callers (e.g. Lambda handlers)
// that manage their own storage connections.
func Migrate(ctx context.Context, logger *log.Entry, caStorage storage.CACertificatesRepo, kmsStorage storage.KMSKeysRepo, dryRun bool) (Result, error) {
	keyMap, err := collectKeys(ctx, logger, caStorage)
	if err != nil {
		return Result{}, fmt.Errorf("collect keys: %w", err)
	}
	logger.Infof("found %d unique keys across CA certificates", len(keyMap))

	ins, skip, fail := runMigration(ctx, logger, kmsStorage, keyMap, dryRun)
	return Result{Inserted: ins, Skipped: skip, Failed: fail}, nil
}

// MigrateWithConfig builds CA and KMS storage from a single Postgres config and runs the
// migration. Both databases ("ca" and "kms") are expected on the same server; the engine
// connects to each automatically. Pass the KMSConfig.Storage field from the standard
// Lamassu service config.
func MigrateWithConfig(ctx context.Context, logger *log.Entry, storageConf cconfig.PluggableStorageEngine, dryRun bool) (Result, error) {
	engine, err := storagebuilder.BuildStorageEngine(logger, storageConf)
	if err != nil {
		return Result{}, fmt.Errorf("build storage engine: %w", err)
	}
	caStorage, err := engine.GetCAStorage()
	if err != nil {
		return Result{}, fmt.Errorf("get CA storage: %w", err)
	}
	kmsStorage, err := engine.GetKMSStorage()
	if err != nil {
		return Result{}, fmt.Errorf("get KMS storage: %w", err)
	}

	return Migrate(ctx, logger, caStorage, kmsStorage, dryRun)
}

// ---------------------------------------------------------------------------
// Internal implementation
// ---------------------------------------------------------------------------

// keyEntry accumulates all data needed to build a models.Key record.
type keyEntry struct {
	engineID    string
	keyID       string // subject_key_id == KMS key_id (SHA-256 hex of PKIX public key)
	algorithm   string
	size        int
	publicKey   string // base64(PEM "PUBLIC KEY")
	name        string // common name of first CA cert using this key
	creationTS  time.Time
	serials     []string // serial numbers of all CA certs using this key
	conflictErr string   // non-empty if the entry cannot be migrated safely
}

// collectKeys scans MANAGED and IMPORTED_WITH_KEY CA certs and groups them by key.
func collectKeys(ctx context.Context, logger *log.Entry, caStorage storage.CACertificatesRepo) (map[string]*keyEntry, error) {
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

		keyID := cert.SubjectKeyID
		if entry, ok := keyMap[keyID]; ok {
			if cert.EngineID != entry.engineID && entry.conflictErr == "" {
				entry.conflictErr = fmt.Sprintf(
					"key %s is referenced by CA certificates with conflicting engine_ids (%q vs %q); "+
						"cannot determine the correct engine — resolve the conflict manually",
					keyID, entry.engineID, cert.EngineID,
				)
			}
			entry.serials = append(entry.serials, cert.SerialNumber)
		} else {
			x509Cert := (*x509.Certificate)(cert.Certificate)

			var algorithm string
			var size int
			switch pub := x509Cert.PublicKey.(type) {
			case *rsa.PublicKey:
				algorithm = "RSA"
				size = pub.N.BitLen()
			case *ecdsa.PublicKey:
				algorithm = "ECDSA"
				size = pub.Params().BitSize
			default:
				logger.Warnf("skipping CA %s: unsupported public key type %T", ca.ID, x509Cert.PublicKey)
				return
			}

			pubKeyDER, err := x509.MarshalPKIXPublicKey(x509Cert.PublicKey)
			if err != nil {
				logger.Errorf("could not marshal public key for CA %s: %s", ca.ID, err)
				return
			}
			pubKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyDER})
			pubKeyB64 := base64.StdEncoding.EncodeToString(pubKeyPEM)

			keyMap[keyID] = &keyEntry{
				engineID:   cert.EngineID,
				keyID:      keyID,
				algorithm:  algorithm,
				size:       size,
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
			return nil, fmt.Errorf("could not list CA certs of type %s: %w", certType, err)
		}
	}

	return keyMap, nil
}

// runMigration inserts missing keys into KMS storage (or logs what it would do in dry-run mode).
// It returns the number of inserted (or would-insert in dry-run), skipped, and failed keys.
func runMigration(ctx context.Context, logger *log.Entry, kmsStorage storage.KMSKeysRepo, keyMap map[string]*keyEntry, dryRun bool) (inserted, skipped, failed int) {
	for _, entry := range keyMap {
		if entry.conflictErr != "" {
			logger.Errorf("skipping key %s: %s", entry.keyID, entry.conflictErr)
			failed++
			continue
		}

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
	return
}
