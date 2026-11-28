package catokms

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	chelpers "github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"gorm.io/gorm"
)

// legacyKMSKeys registers keys in a kms schema the key identity migration has not reached yet, such as the one Lamassu
// 3.8 leaves: kms_keys has neither id nor digest, which the KMS repository reads and writes. It implements the part of
// storage.KMSKeysRepo that runMigration uses. The digest of every stored public key is computed here, the way the kms
// migration computes it later, so a key the KMS already stores under another name is found by its public key.
type legacyKMSKeys struct {
	storage.KMSKeysRepo
	db       *gorm.DB
	byDigest map[string][]*models.Key
}

func newLegacyKMSKeys(ctx context.Context, db *gorm.DB) (*legacyKMSKeys, error) {
	var rows []struct{ KeyID, EngineID, PublicKey string }
	if err := db.WithContext(ctx).Raw(`SELECT key_id, engine_id, public_key FROM kms_keys`).Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("read the keys of the kms: %w", err)
	}

	l := &legacyKMSKeys{db: db, byDigest: map[string][]*models.Key{}}
	for _, r := range rows {
		// A public key that cannot be read has no digest: no key is found through it, and the kms migration stops on it
		// and names it.
		digest, err := chelpers.StoredPublicKeyDigest(r.PublicKey)
		if err != nil {
			continue
		}
		l.byDigest[digest] = append(l.byDigest[digest], &models.Key{KeyID: r.KeyID, EngineID: r.EngineID, Digest: digest})
	}
	return l, nil
}

func (l *legacyKMSKeys) SelectExistsByKeyID(ctx context.Context, keyID, engineID string) (bool, *models.Key, error) {
	var n int64
	if err := l.db.WithContext(ctx).Raw(`SELECT count(*) FROM kms_keys WHERE key_id = ? AND engine_id = ?`, keyID, engineID).
		Scan(&n).Error; err != nil {
		return false, nil, err
	}
	if n == 0 {
		return false, nil, nil
	}
	return true, &models.Key{KeyID: keyID, EngineID: engineID}, nil
}

func (l *legacyKMSKeys) SelectByDigest(_ context.Context, digest string) ([]*models.Key, error) {
	return l.byDigest[digest], nil
}

// Insert writes the columns the kms schema of 3.8 has: the kms migration adds the id and computes the digest.
func (l *legacyKMSKeys) Insert(ctx context.Context, key *models.Key) (*models.Key, error) {
	metadata, err := json.Marshal(key.Metadata)
	if err != nil {
		return nil, err
	}
	aliases, err := json.Marshal(key.Aliases)
	if err != nil {
		return nil, err
	}
	tags, err := json.Marshal(key.Tags)
	if err != nil {
		return nil, err
	}

	if err := l.db.WithContext(ctx).Exec(`INSERT INTO kms_keys
		(key_id, engine_id, name, algorithm, size, public_key, has_private_key, creation_ts, metadata, aliases, tags)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?::jsonb, ?::jsonb, ?::jsonb)`,
		key.KeyID, key.EngineID, key.Name, key.Algorithm, key.Size, key.PublicKey, key.HasPrivateKey, key.CreationTS,
		string(metadata), string(aliases), string(tags)).Error; err != nil {
		return nil, err
	}

	l.byDigest[key.Digest] = append(l.byDigest[key.Digest], &models.Key{KeyID: key.KeyID, EngineID: key.EngineID, Digest: key.Digest})
	return key, nil
}
