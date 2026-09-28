package assemblers

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/config"
	lservices "github.com/lamassuiot/lamassuiot/backend/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/storage/builder"
	core "github.com/lamassuiot/lamassuiot/core/v3"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/engines/crypto/filesystem/v3"
	log "github.com/sirupsen/logrus"
)

const tenantKeyMigrationActor = "kms-tenant-key-migration"

// globalFilesystemEngine es un engine filesystem sin tenant_id cuya raíz plana
// puede contener claves anteriores a las instancias por tenant.
type globalFilesystemEngine struct {
	engineID         string
	storageDirectory string
	engine           *lservices.Engine
}

// tenantKeyMigrationResult son los recuentos de una ejecución. Pending cuenta
// las claves cuyo original se conserva porque algún tenant no se pudo leer
// (suspendido); Orphans, las claves sin fila en ningún tenant.
type tenantKeyMigrationResult struct {
	Moved           int
	AlreadyMigrated int
	Orphans         int
	Pending         int
	Errors          int
}

type tenantKeyRef struct {
	tenantID  string
	publicKey string
}

// migrateTenantKeys es el paso de arranque de KMS de 004 T4.6: mueve las claves
// de la raíz plana de cada engine filesystem global a tenants/<tenant>/.
func migrateTenantKeys(logger *log.Entry, conf config.KMSConfig, engines map[string]*lservices.Engine, kmsStorage storage.KMSKeysRepo) error {
	globals, err := globalFilesystemEngines(conf, engines)
	if err != nil {
		return err
	}
	if len(globals) == 0 {
		return nil
	}
	lister := func() (storage.NonDeletedTenantLister, error) {
		return nonDeletedTenantLister(logger, conf.Storage)
	}
	_, err = migrateGlobalFilesystemKeysToTenants(context.Background(), logger, globals, lister, kmsStorage)
	return err
}

func globalFilesystemEngines(conf config.KMSConfig, engines map[string]*lservices.Engine) ([]globalFilesystemEngine, error) {
	var globals []globalFilesystemEngine
	for _, cfg := range conf.CryptoEngineConfig.CryptoEngines {
		engine, ok := engines[cfg.ID]
		if !ok || cfg.Type != cconfig.FilesystemProvider || cfg.TenantID != "" || engine.DeriveForTenant == nil {
			continue
		}
		fsConfig, err := cconfig.CryptoEngineConfigAdapter[filesystem.FilesystemEngineConfig]{}.Marshal(cfg)
		if err != nil {
			return nil, fmt.Errorf("could not read the configuration of engine %s: %w", cfg.ID, err)
		}
		globals = append(globals, globalFilesystemEngine{
			engineID:         cfg.ID,
			storageDirectory: fsConfig.Config.StorageDirectory,
			engine:           engine,
		})
	}
	return globals, nil
}

func nonDeletedTenantLister(logger *log.Entry, storageConfig cconfig.PluggableStorageEngine) (storage.NonDeletedTenantLister, error) {
	engine, err := builder.BuildStorageEngine(logger, storageConfig)
	if err != nil {
		return nil, fmt.Errorf("could not create storage engine: %w", err)
	}
	memberships, err := engine.GetControlPlaneMembershipStorage()
	if err != nil {
		return nil, fmt.Errorf("could not get control plane storage: %w", err)
	}
	lister, ok := memberships.(storage.NonDeletedTenantLister)
	if !ok {
		return nil, errors.New("control plane storage cannot list tenants")
	}
	return lister, nil
}

func migrateGlobalFilesystemKeysToTenants(ctx context.Context, logger *log.Entry, globals []globalFilesystemEngine, lister func() (storage.NonDeletedTenantLister, error), kmsStorage storage.KMSKeysRepo) (tenantKeyMigrationResult, error) {
	result := tenantKeyMigrationResult{}
	lMig := logger.WithField("step", "tenant-key-migration")

	flatKeys := map[string][]string{}
	total := 0
	for _, global := range globals {
		keyIDs, err := global.engine.Service.ListPrivateKeyIDs()
		if err != nil {
			return result, fmt.Errorf("could not list the flat root of engine %s: %w", global.engineID, err)
		}
		sort.Strings(keyIDs)
		flatKeys[global.engineID] = keyIDs
		total += len(keyIDs)
	}
	if total == 0 {
		lMig.Infof("no keys left in the flat root of global filesystem engines")
		return result, nil
	}

	tenantLister, err := lister()
	if err != nil {
		return result, fmt.Errorf("could not list tenants to migrate %d keys of the flat root: %w", total, err)
	}
	tenants, err := tenantLister.ListNonDeletedTenants(ctx)
	if err != nil {
		return result, fmt.Errorf("could not list tenants: %w", err)
	}

	refs := map[string]map[string][]tenantKeyRef{}
	for _, global := range globals {
		refs[global.engineID] = map[string][]tenantKeyRef{}
	}
	var unreadable []string
	for _, tenant := range tenants {
		if tenant.Status == models.TenantSuspended {
			unreadable = append(unreadable, tenant.ID)
			continue
		}
		tenantCtx := core.WithTenantContext(ctx, core.TenantContext{
			OrganizationID: tenant.OrganizationID,
			TenantID:       tenant.ID,
			ActorID:        tenantKeyMigrationActor,
			ActorType:      "system",
			CorrelationID:  tenantKeyMigrationActor + "-" + tenant.ID,
			Source:         tenantKeyMigrationActor,
			TenantStatus:   tenant.Status,
			Validated:      true,
		})
		_, err := kmsStorage.SelectAll(tenantCtx, storage.StorageListRequest[models.Key]{
			ExhaustiveRun: true,
			ApplyFunc: func(key models.Key) {
				if engineRefs, ok := refs[key.EngineID]; ok {
					engineRefs[key.KeyID] = append(engineRefs[key.KeyID], tenantKeyRef{tenantID: tenant.ID, publicKey: key.PublicKey})
				}
			},
		})
		if err != nil {
			return result, fmt.Errorf("could not read the keys of tenant %s: %w", tenant.ID, err)
		}
	}
	if len(unreadable) > 0 {
		lMig.Warnf("suspended tenants cannot be read, flat root originals are kept until they are active: %v", unreadable)
	}

	for _, global := range globals {
		if err := migrateEngineFlatRoot(lMig.WithField("engine", global.engineID), global, flatKeys[global.engineID], refs[global.engineID], len(unreadable) > 0, &result); err != nil {
			return result, err
		}
	}

	lMig.Infof("tenant key migration finished: moved=%d already_migrated=%d orphans=%d pending=%d errors=%d",
		result.Moved, result.AlreadyMigrated, result.Orphans, result.Pending, result.Errors)
	if result.Errors > 0 {
		return result, fmt.Errorf("tenant key migration found %d errors: no original with errors was removed", result.Errors)
	}
	return result, nil
}

func migrateEngineFlatRoot(logger *log.Entry, global globalFilesystemEngine, keyIDs []string, refs map[string][]tenantKeyRef, someTenantUnreadable bool, result *tenantKeyMigrationResult) error {
	if len(keyIDs) == 0 {
		return nil
	}
	root, err := os.OpenRoot(global.storageDirectory)
	if err != nil {
		return fmt.Errorf("could not open the flat root of engine %s: %w", global.engineID, err)
	}
	defer root.Close()

	instances := map[string]cryptoengines.CryptoEngine{}
	defer func() {
		for _, instance := range instances {
			if closer, ok := instance.(io.Closer); ok {
				_ = closer.Close()
			}
		}
	}()
	tenantInstance := func(tenantID string) (cryptoengines.CryptoEngine, error) {
		if instance, ok := instances[tenantID]; ok {
			return instance, nil
		}
		instance, err := global.engine.DeriveForTenant(tenantID)
		if err != nil {
			return nil, err
		}
		instances[tenantID] = instance
		return instance, nil
	}

	for _, keyID := range keyIDs {
		keyRefs := refs[keyID]
		if len(keyRefs) == 0 {
			if someTenantUnreadable {
				result.Pending++
				logger.Warnf("key %s has no row in the readable tenants: kept in the flat root", keyID)
			} else {
				result.Orphans++
				logger.Warnf("orphan key %s in the flat root: no tenant has it, it is neither assigned nor removed", keyID)
			}
			continue
		}

		verified := true
		for _, ref := range keyRefs {
			moved, err := linkKeyToTenant(root, tenantInstance, keyID, ref)
			switch {
			case err != nil:
				verified = false
				result.Errors++
				logger.Errorf("could not migrate key %s to tenant %s: %s", keyID, ref.tenantID, err)
			case moved:
				result.Moved++
			default:
				result.AlreadyMigrated++
			}
		}
		if !verified {
			continue
		}
		if someTenantUnreadable {
			result.Pending++
			continue
		}
		if err := root.Remove(keyID); err != nil {
			result.Errors++
			logger.Errorf("could not remove the migrated original of key %s: %s", keyID, err)
		}
	}
	return nil
}

// linkKeyToTenant enlaza <dir>/<keyID> en tenants/<tenant>/<keyID> y comprueba
// que la instancia del tenant lee una clave con la clave pública de su fila.
// moved es false si el destino ya existía (ejecución anterior interrumpida).
func linkKeyToTenant(root *os.Root, tenantInstance func(string) (cryptoengines.CryptoEngine, error), keyID string, ref tenantKeyRef) (bool, error) {
	instance, err := tenantInstance(ref.tenantID)
	if err != nil {
		return false, fmt.Errorf("could not open the tenant root: %w", err)
	}
	destination := filepath.Join("tenants", ref.tenantID, keyID)
	existed := true
	if _, err := root.Lstat(destination); errors.Is(err, os.ErrNotExist) {
		existed = false
		if err := root.Link(keyID, destination); err != nil {
			return false, fmt.Errorf("could not link the key: %w", err)
		}
	} else if err != nil {
		return false, err
	}

	if err := verifyTenantKey(instance, keyID, ref.publicKey); err != nil {
		if !existed {
			_ = root.Remove(destination)
		}
		return false, err
	}
	return !existed, nil
}

func verifyTenantKey(instance cryptoengines.CryptoEngine, keyID, encodedPublicKey string) error {
	expected, err := decodeKMSPublicKey(encodedPublicKey)
	if err != nil {
		return fmt.Errorf("could not decode the public key of the row: %w", err)
	}
	signer, err := instance.GetPrivateKeyByID(keyID)
	if err != nil {
		return fmt.Errorf("could not read the tenant copy: %w", err)
	}
	public, ok := signer.Public().(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !public.Equal(expected) {
		return errors.New("the tenant copy does not match the public key of the row")
	}
	return nil
}

// decodeKMSPublicKey decodifica kms_keys.public_key: base64 de un PEM
// «PUBLIC KEY».
func decodeKMSPublicKey(encoded string) (crypto.PublicKey, error) {
	pemBytes, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("not a PEM block")
	}
	return x509.ParsePKIXPublicKey(block.Bytes)
}
