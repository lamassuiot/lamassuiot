package services

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/cryptoengines"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	chelpers "github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// importEngine holds keys by name and names an imported key after its digest, as every crypto engine does.
type importEngine struct {
	cryptoengines.CryptoEngine
	keys map[string]crypto.Signer
}

func (e *importEngine) GetEngineConfig() models.CryptoEngineInfo {
	return models.CryptoEngineInfo{SupportedKeyTypes: []models.SupportedKeyTypeInfo{{Type: models.KeyType(x509.ECDSA), Sizes: []int{256}}}}
}

func (e *importEngine) ImportECDSAPrivateKey(_ context.Context, key *ecdsa.PrivateKey) (string, crypto.Signer, error) {
	name, err := chelpers.PublicKeyDigest(&key.PublicKey)
	if err != nil {
		return "", nil, err
	}
	e.keys[name] = key
	return name, key, nil
}

func (e *importEngine) GetPrivateKeyByID(_ context.Context, name string) (crypto.Signer, error) {
	if k, ok := e.keys[name]; ok {
		return k, nil
	}
	return nil, errors.New("key not found")
}

// importRows keeps rows by (key_id, engine_id) and enforces the two unique constraints of kms_keys.
type importRows struct {
	storage.KMSKeysRepo
	rows map[string]*models.Key
}

func (r *importRows) SelectByDigest(_ context.Context, digest string) ([]*models.Key, error) {
	var out []*models.Key
	for _, k := range r.rows {
		if k.Digest == digest {
			c := *k
			out = append(out, &c)
		}
	}
	return out, nil
}

func (r *importRows) SelectExistsByKeyID(_ context.Context, keyID, engineID string) (bool, *models.Key, error) {
	k, ok := r.rows[keyID+"@"+engineID]
	if !ok {
		return false, nil, nil
	}
	c := *k
	return true, &c, nil
}

func (r *importRows) Insert(_ context.Context, key *models.Key) (*models.Key, error) {
	for _, k := range r.rows {
		if (k.KeyID == key.KeyID || k.Digest == key.Digest) && k.EngineID == key.EngineID {
			return nil, errors.New("duplicate key value violates unique constraint")
		}
	}
	c := *key
	r.rows[key.KeyID+"@"+key.EngineID] = &c
	return key, nil
}

func (r *importRows) Update(_ context.Context, key *models.Key) (*models.Key, error) {
	if _, ok := r.rows[key.KeyID+"@"+key.EngineID]; !ok {
		return nil, errors.New("record not found")
	}
	c := *key
	r.rows[key.KeyID+"@"+key.EngineID] = &c
	return key, nil
}

func (r *importRows) RenameKey(_ context.Context, engineID, oldKeyID, newKeyID string, renameInEngine func() error) (bool, error) {
	k, ok := r.rows[oldKeyID+"@"+engineID]
	if !ok {
		return false, nil
	}
	if err := renameInEngine(); err != nil {
		return false, err
	}
	delete(r.rows, oldKeyID+"@"+engineID)
	k.KeyID = newKeyID
	k.Aliases = append(k.Aliases, oldKeyID)
	r.rows[newKeyID+"@"+engineID] = k
	return true, nil
}

func newImportService(t *testing.T) (*KMSServiceBackend, *importEngine, *importRows) {
	t.Helper()
	kmsValidator = validator.New()
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	eng := &importEngine{keys: map[string]crypto.Signer{}}
	var ce cryptoengines.CryptoEngine = eng
	rows := &importRows{rows: map[string]*models.Key{}}
	return &KMSServiceBackend{kmsStorage: rows, logger: logrus.NewEntry(logger), cryptoEngines: map[string]*cryptoengines.CryptoEngine{"e1": &ce},
		defaultCryptoEngine: &ce, defaultCryptoEngineID: "e1"}, eng, rows
}

func storedPublicKey(t *testing.T, key *ecdsa.PrivateKey) (string, string) {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	digest, err := chelpers.PublicKeyDigest(&key.PublicKey)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), digest
}

// Importing a key whose public key the engine already has a row for: the row is reused when nothing holds the key
// (a row a deleted CA left behind, or one registered with its public key only), and the import is refused when the
// engine holds it, instead of failing on the unique (digest, engine_id) of kms_keys.
func TestImportKeyOverAnExistingRowOfItsPublicKey(t *testing.T) {
	ctx := context.Background()
	newKey := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		return k
	}

	t.Run("a key no row knows is stored under its digest", func(t *testing.T) {
		svc, eng, rows := newImportService(t)
		key := newKey()
		_, digest := storedPublicKey(t, key)
		got, err := svc.ImportKey(ctx, services.ImportKeyInput{PrivateKey: key, EngineID: "e1", Name: "fresh"})
		require.NoError(t, err)
		require.Equal(t, digest, got.KeyID)
		require.Contains(t, eng.keys, digest)
		require.Len(t, rows.rows, 1)
	})

	t.Run("a row whose name the engine does not hold is taken over", func(t *testing.T) {
		svc, eng, rows := newImportService(t)
		key := newKey()
		pub, digest := storedPublicKey(t, key)
		const ski = "5a1b2c3d4e5f60718293a4b5c6d7e8f901234567"
		rows.rows[ski+"@e1"] = &models.Key{KeyID: ski, EngineID: "e1", Digest: digest, PublicKey: pub, HasPrivateKey: true, Aliases: []string{"kept"}}

		got, err := svc.ImportKey(ctx, services.ImportKeyInput{PrivateKey: key, EngineID: "e1"})
		require.NoError(t, err)
		require.Equal(t, digest, got.KeyID, "the row now carries the name the engine holds the key under")
		require.True(t, got.HasPrivateKey)
		require.ElementsMatch(t, []string{"kept", ski}, got.Aliases, "the old name stays as an alias")
		require.Len(t, rows.rows, 1, "no second row")
		require.Contains(t, eng.keys, digest)
	})

	t.Run("a row with the public key only gets the private key", func(t *testing.T) {
		svc, _, rows := newImportService(t)
		key := newKey()
		pub, digest := storedPublicKey(t, key)
		rows.rows[digest+"@e1"] = &models.Key{KeyID: digest, EngineID: "e1", Digest: digest, PublicKey: pub, HasPrivateKey: false, Aliases: []string{}}

		got, err := svc.ImportKey(ctx, services.ImportKeyInput{PrivateKey: key, EngineID: "e1"})
		require.NoError(t, err)
		require.Equal(t, digest, got.KeyID)
		require.True(t, got.HasPrivateKey)
		require.True(t, rows.rows[digest+"@e1"].HasPrivateKey)
		require.Len(t, rows.rows, 1)
	})

	t.Run("a key the engine already holds is refused", func(t *testing.T) {
		svc, eng, rows := newImportService(t)
		key := newKey()
		pub, digest := storedPublicKey(t, key)
		eng.keys[digest] = key
		rows.rows[digest+"@e1"] = &models.Key{KeyID: digest, EngineID: "e1", Digest: digest, PublicKey: pub, HasPrivateKey: true, Name: "original"}

		_, err := svc.ImportKey(ctx, services.ImportKeyInput{PrivateKey: key, EngineID: "e1", Name: "again"})
		require.ErrorIs(t, err, errs.ErrKeyAlreadyExists)
		require.Equal(t, "original", rows.rows[digest+"@e1"].Name, "the stored key is left as it was")
	})

	t.Run("a key the engine holds under its SKI is refused, and no second copy is written", func(t *testing.T) {
		svc, eng, rows := newImportService(t)
		key := newKey()
		pub, digest := storedPublicKey(t, key)
		const ski = "6b2c3d4e5f60718293a4b5c6d7e8f9012345678a"
		eng.keys[ski] = key
		rows.rows[ski+"@e1"] = &models.Key{KeyID: ski, EngineID: "e1", Digest: digest, PublicKey: pub, HasPrivateKey: true}

		_, err := svc.ImportKey(ctx, services.ImportKeyInput{PrivateKey: key, EngineID: "e1"})
		require.ErrorIs(t, err, errs.ErrKeyAlreadyExists)
		require.NotContains(t, eng.keys, digest, "the engine is not given a second copy under the digest")
		require.Len(t, eng.keys, 1)
		require.Contains(t, eng.keys, ski)
		require.Len(t, rows.rows, 1)
	})
}
