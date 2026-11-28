package catokms

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"slices"
	"sort"
	"time"

	storagebuilder "github.com/lamassuiot/lamassuiot/v4/backend/pkg/storage/builder"
	cconfig "github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	chelpers "github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// Result summarises the outcome of a migration run.
type Result struct {
	Inserted int
	Skipped  int
	Failed   int
}

// CALister lists the CAs of a type; storage.CACertificatesRepo is one.
type CALister interface {
	SelectByType(ctx context.Context, caType models.CertificateType, req storage.StorageListRequest[models.CACertificate]) (string, error)
}

// Migrate runs the migration using pre-built storage instances.
// This is the primary entry point for programmatic callers (e.g. Lambda handlers)
// that manage their own storage connections.
func Migrate(ctx context.Context, logger *log.Entry, caStorage CALister, kmsStorage storage.KMSKeysRepo, dryRun bool) (Result, error) {
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
//
// CAs are read from the ca tables, not through the CA repository: the tool runs before the ca
// migrations, which need the keys it registers, and the repository reads what they create. For the
// same reason it runs on the kms schema of 3.8: the upgrade order is this tool, then the kms, ca and
// va migrations. Run again after the upgrade, it reads the migrated kms schema.
func MigrateWithConfig(ctx context.Context, logger *log.Entry, storageConf cconfig.PluggableStorageEngine, dryRun bool) (Result, error) {
	engine, err := storagebuilder.BuildStorageEngine(logger, storageConf)
	if err != nil {
		return Result{}, fmt.Errorf("build storage engine: %w", err)
	}
	pg, ok := engine.(*postgres.PostgresStorageEngine)
	if !ok {
		return Result{}, fmt.Errorf("unsupported storage provider %s: only postgres is supported", storageConf.Provider)
	}
	caDB, err := postgres.CreatePostgresDBConnection(logger, pg.Config, postgres.CA_SCHEMA)
	if err != nil {
		return Result{}, fmt.Errorf("connect to CA storage: %w", err)
	}
	caStorage, err := postgres.NewCATableReader(logger, caDB)
	if err != nil {
		return Result{}, fmt.Errorf("get CA storage: %w", err)
	}
	kmsDB, err := postgres.CreatePostgresDBConnection(logger, pg.Config, postgres.KMS_SCHEMA)
	if err != nil {
		return Result{}, fmt.Errorf("connect to KMS storage: %w", err)
	}
	identity, err := hasKeyIdentity(kmsDB)
	if err != nil {
		return Result{}, err
	}
	var kmsStorage storage.KMSKeysRepo
	if identity {
		kmsStorage, err = engine.GetKMSStorage()
		if err != nil {
			return Result{}, fmt.Errorf("get KMS storage: %w", err)
		}
	} else {
		logger.Infof("the kms schema has no key identity yet: registering the keys in the kms schema of 3.8, whose migration computes their digest")
		kmsStorage, err = newLegacyKMSKeys(ctx, kmsDB)
		if err != nil {
			return Result{}, err
		}
	}

	return Migrate(ctx, logger, caStorage, kmsStorage, dryRun)
}

// hasKeyIdentity reports whether the kms schema has the key identity migration (kms_keys.digest), which the KMS
// repository needs. Without it the tool writes the columns of the kms schema of 3.8.
func hasKeyIdentity(db *gorm.DB) (bool, error) {
	var migrated bool
	if err := db.Raw(`SELECT EXISTS (SELECT 1 FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = 'kms_keys' AND column_name = 'digest')`).Scan(&migrated).Error; err != nil {
		return false, fmt.Errorf("check the kms schema: %w", err)
	}
	return migrated, nil
}

// ---------------------------------------------------------------------------
// Internal implementation
// ---------------------------------------------------------------------------

// keyEntry accumulates all data needed to build a models.Key record.
type keyEntry struct {
	engineID    string
	keyID       string // the CA's subject_key_id: crypto engines before the KMS named the keys of imported CAs after it
	digest      string // SHA-256 hex of the PKIX public key: the name the KMS gives every key it stores
	algorithm   string
	size        int
	publicKey   string // base64(PEM "PUBLIC KEY")
	name        string // common name of first CA cert using this key
	creationTS  time.Time
	serials     []string // serial numbers of all CA certs using this key
	conflictErr string   // non-empty if the entry cannot be migrated safely
}

// collectKeys scans MANAGED and IMPORTED_WITH_KEY CA certs and groups them by key.
func collectKeys(ctx context.Context, logger *log.Entry, caStorage CALister) (map[string]*keyEntry, error) {
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
			digest, err := chelpers.PublicKeyDigest(x509Cert.PublicKey)
			if err != nil {
				logger.Errorf("could not compute the digest of the public key of CA %s: %s", ca.ID, err)
				return
			}

			keyMap[keyID] = &keyEntry{
				engineID:   cert.EngineID,
				keyID:      keyID,
				digest:     digest,
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
	// Certificates can share a public key under different SKIs, and the KMS stores a public key once per engine. The
	// SKIs are walked in order, so the one that names the key does not depend on the order of the map.
	skis := make([]string, 0, len(keyMap))
	for ski := range keyMap {
		skis = append(skis, ski)
	}
	sort.Strings(skis)
	registered := map[string]string{} // engine|digest -> SKI the key is registered under in this run

	for _, ski := range skis {
		entry := keyMap[ski]
		if entry.conflictErr != "" {
			logger.Errorf("skipping key %s: %s", entry.keyID, entry.conflictErr)
			failed++
			continue
		}

		exists, _, err := kmsStorage.SelectExistsByKeyID(ctx, entry.keyID, entry.engineID)
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

		// The key may already be stored under another name: a CA imported since the KMS exists has it under the digest of
		// its public key, while its SKI is the one its issuer wrote, and a certificate that shares the key of another has
		// another SKI. Registering it again would add a row no crypto engine holds, or break the unique (digest,
		// engine_id) of the KMS.
		if entry.digest != "" {
			holder := entry.engineID + "|" + entry.digest
			if by, ok := registered[holder]; ok {
				logger.Infof("key %s has the public key of %s, registered earlier in this run — skipping", entry.keyID, by)
				skipped++
				continue
			}
			copies, err := kmsStorage.SelectByDigest(ctx, entry.digest)
			if err != nil {
				logger.Errorf("could not check the public key of %s in KMS storage: %s", entry.keyID, err)
				failed++
				continue
			}
			if i := slices.IndexFunc(copies, func(k *models.Key) bool { return k.EngineID == entry.engineID }); i >= 0 {
				logger.Infof("key %s already in KMS storage as %s, with the same public key — skipping", entry.keyID, copies[i].KeyID)
				skipped++
				continue
			}
		}

		key := &models.Key{
			KeyID:         entry.keyID,
			Digest:        entry.digest,
			EngineID:      entry.engineID,
			Name:          entry.name,
			Aliases:       []string{},
			HasPrivateKey: true,
			Algorithm:     entry.algorithm,
			Size:          entry.size,
			PublicKey:     entry.publicKey,
			CreationTS:    entry.creationTS,
			Tags:          []string{},
			Metadata:      map[string]any{},
		}

		logger.Infof("key %s — engine=%s alg=%s bits=%d certificates=%d",
			entry.keyID, entry.engineID, entry.algorithm, entry.size, len(entry.serials))

		if dryRun {
			inserted++ // count as "would insert"
			registered[entry.engineID+"|"+entry.digest] = entry.keyID
			continue
		}

		if _, err = kmsStorage.Insert(ctx, key); err != nil {
			logger.Errorf("could not insert key %s: %s", entry.keyID, err)
			failed++
			continue
		}
		inserted++
		registered[entry.engineID+"|"+entry.digest] = entry.keyID
	}

	action := "inserted"
	if dryRun {
		action = "would insert"
	}
	logger.Infof("migration complete: %s=%d skipped=%d failed=%d", action, inserted, skipped, failed)
	return
}
