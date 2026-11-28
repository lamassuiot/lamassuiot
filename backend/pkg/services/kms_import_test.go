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
	keys    map[string]crypto.Signer
	getErr   error // when set, every GetPrivateKeyByID fails with it, as an HSM whose session dropped
	listErr  error
	onImport func() // runs while a key is imported, as another request that arrives meanwhile
}

func (e *importEngine) ListPrivateKeyIDs(context.Context) ([]string, error) {
	if e.listErr != nil {
		return nil, e.listErr
	}
	var ids []string
	for k := range e.keys {
		ids = append(ids, k)
	}
	return ids, nil
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
	if e.onImport != nil {
		e.onImport()
	}
	return name, key, nil
}

func (e *importEngine) GetPrivateKeyByID(_ context.Context, name string) (crypto.Signer, error) {
	if e.getErr != nil {
		return nil, e.getErr
	}
	if k, ok := e.keys[name]; ok {
		return k, nil
	}
	return nil, errors.New("key not found")
}

// importRows keeps rows by (key_id, engine_id) and enforces the two unique constraints of kms_keys.
type importRows struct {
	storage.KMSKeysRepo
	rows      map[string]*models.Key
	selectErr error // when set, SelectByDigest fails with it, as a database that cannot be reached
	recordErr error // when set, RecordPrivateKey fails with it
}

func (r *importRows) SelectByDigest(_ context.Context, digest string) ([]*models.Key, error) {
	if r.selectErr != nil {
		return nil, r.selectErr
	}
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

func (r *importRows) RecordPrivateKey(_ context.Context, keyID, engineID, name string) (*models.Key, error) {
	if r.recordErr != nil {
		return nil, r.recordErr
	}
	k, ok := r.rows[keyID+"@"+engineID]
	if !ok {
		return nil, errs.ErrKeyNotFound
	}
	k.HasPrivateKey = true
	if k.Name == "" {
		k.Name = name
	}
	c := *k
	return &c, nil
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

// Importing a key whose public key the engine already has a row for, instead of failing on the unique (digest,
// engine_id) of kms_keys: a row named by the digest gets the private key when the engine does not hold it (a row
// registered with its public key only, or one whose key the engine lost), and the import is refused when the engine
// holds it or when the row has another name, before anything is written to the engine.
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

	t.Run("a row under another name than the digest is refused, and nothing is written", func(t *testing.T) {
		svc, eng, rows := newImportService(t)
		key := newKey()
		pub, digest := storedPublicKey(t, key)
		const ski = "5a1b2c3d4e5f60718293a4b5c6d7e8f901234567"
		rows.rows[ski+"@e1"] = &models.Key{KeyID: ski, EngineID: "e1", Digest: digest, PublicKey: pub, HasPrivateKey: true, Aliases: []string{"kept"}}

		_, err := svc.ImportKey(ctx, services.ImportKeyInput{PrivateKey: key, EngineID: "e1"})
		require.ErrorIs(t, err, errs.ErrKeyAlreadyExists)
		require.ErrorContains(t, err, ski, "the error names the row that stores the public key")
		require.Empty(t, eng.keys, "nothing is written to the engine")
		require.Len(t, rows.rows, 1)
		require.Equal(t, []string{"kept"}, rows.rows[ski+"@e1"].Aliases, "the row is left as it was")
	})

	t.Run("a row named by the digest whose key the engine lost gets it back", func(t *testing.T) {
		svc, eng, rows := newImportService(t)
		key := newKey()
		pub, digest := storedPublicKey(t, key)
		rows.rows[digest+"@e1"] = &models.Key{KeyID: digest, EngineID: "e1", Digest: digest, PublicKey: pub, HasPrivateKey: true, Name: "original", Aliases: []string{"kept"}}

		got, err := svc.ImportKey(ctx, services.ImportKeyInput{PrivateKey: key, EngineID: "e1", Name: "again"})
		require.NoError(t, err)
		require.Equal(t, digest, got.KeyID)
		require.True(t, got.HasPrivateKey)
		require.Equal(t, "original", got.Name, "a row that has a name keeps it")
		require.Equal(t, []string{"kept"}, got.Aliases)
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

	t.Run("what is saved in the row while the key is imported is kept", func(t *testing.T) {
		svc, eng, rows := newImportService(t)
		key := newKey()
		pub, digest := storedPublicKey(t, key)
		rows.rows[digest+"@e1"] = &models.Key{KeyID: digest, EngineID: "e1", Digest: digest, PublicKey: pub, Aliases: []string{"old"}, Tags: []string{}, Metadata: map[string]any{}}
		eng.onImport = func() {
			row := rows.rows[digest+"@e1"]
			row.Name = "renamed meanwhile"
			row.Aliases = []string{"old", "added meanwhile"}
			row.Tags = []string{"tagged meanwhile"}
			row.Metadata = map[string]any{"edited": "meanwhile"}
		}

		got, err := svc.ImportKey(ctx, services.ImportKeyInput{PrivateKey: key, EngineID: "e1", Name: "import"})
		require.NoError(t, err)
		require.True(t, got.HasPrivateKey)
		stored := rows.rows[digest+"@e1"]
		require.True(t, stored.HasPrivateKey)
		require.Equal(t, "renamed meanwhile", stored.Name, "a name given meanwhile is not replaced")
		require.Equal(t, []string{"old", "added meanwhile"}, stored.Aliases)
		require.Equal(t, []string{"tagged meanwhile"}, stored.Tags)
		require.Equal(t, map[string]any{"edited": "meanwhile"}, stored.Metadata)
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

	t.Run("an engine that fails to read a key it holds is not taken for one that lost it", func(t *testing.T) {
		svc, eng, rows := newImportService(t)
		key := newKey()
		pub, digest := storedPublicKey(t, key)
		eng.keys[digest] = key
		eng.getErr = errors.New("CKR_SESSION_HANDLE_INVALID")
		rows.rows[digest+"@e1"] = &models.Key{KeyID: digest, EngineID: "e1", Digest: digest, PublicKey: pub, HasPrivateKey: true, Name: "original"}

		_, err := svc.ImportKey(ctx, services.ImportKeyInput{PrivateKey: key, EngineID: "e1", Name: "again"})
		require.ErrorIs(t, err, errs.ErrKeyAlreadyExists, "the engine lists the key: it holds it")
		require.Equal(t, "original", rows.rows[digest+"@e1"].Name, "the row is left as it was")
	})

	t.Run("an engine that cannot say whether it holds the key stops the import", func(t *testing.T) {
		svc, eng, rows := newImportService(t)
		key := newKey()
		pub, digest := storedPublicKey(t, key)
		eng.getErr = errors.New("throttled")
		eng.listErr = errors.New("throttled")
		rows.rows[digest+"@e1"] = &models.Key{KeyID: digest, EngineID: "e1", Digest: digest, PublicKey: pub, HasPrivateKey: true, Name: "original"}

		_, err := svc.ImportKey(ctx, services.ImportKeyInput{PrivateKey: key, EngineID: "e1", Name: "again"})
		require.Error(t, err)
		require.NotErrorIs(t, err, errs.ErrKeyAlreadyExists)
		require.Empty(t, eng.keys, "nothing is written to the engine")
		require.Equal(t, "original", rows.rows[digest+"@e1"].Name, "the row is left as it was")
	})
}

// A failure of the engine or of the storage during an import is logged, and the caller gets a message that names
// neither: the text of an engine or a database error can carry hosts, URLs or ARNs.
func TestImportKeyKeepsInternalErrorsFromTheCaller(t *testing.T) {
	ctx := context.Background()
	newKey := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		return k
	}
	const internal = "dial tcp 10.0.12.7:8200: arn:aws:kms:eu-west-1:123456789012:key/secret refused"

	t.Run("the storage fails to look the public key up", func(t *testing.T) {
		svc, _, rows := newImportService(t)
		rows.selectErr = errors.New(internal)
		_, err := svc.ImportKey(ctx, services.ImportKeyInput{PrivateKey: newKey(), EngineID: "e1"})
		require.Error(t, err)
		require.NotContains(t, err.Error(), "10.0.12.7")
	})

	t.Run("the engine cannot say whether it holds the key", func(t *testing.T) {
		svc, eng, rows := newImportService(t)
		key := newKey()
		pub, digest := storedPublicKey(t, key)
		eng.getErr = errors.New(internal)
		eng.listErr = errors.New(internal)
		rows.rows[digest+"@e1"] = &models.Key{KeyID: digest, EngineID: "e1", Digest: digest, PublicKey: pub, HasPrivateKey: true}
		_, err := svc.ImportKey(ctx, services.ImportKeyInput{PrivateKey: key, EngineID: "e1"})
		require.Error(t, err)
		require.NotContains(t, err.Error(), "10.0.12.7")
	})

	t.Run("the storage fails to record the private key", func(t *testing.T) {
		svc, _, rows := newImportService(t)
		key := newKey()
		pub, digest := storedPublicKey(t, key)
		rows.rows[digest+"@e1"] = &models.Key{KeyID: digest, EngineID: "e1", Digest: digest, PublicKey: pub}
		rows.recordErr = errors.New(internal)
		_, err := svc.ImportKey(ctx, services.ImportKeyInput{PrivateKey: key, EngineID: "e1"})
		require.Error(t, err)
		require.NotContains(t, err.Error(), "10.0.12.7")
	})

	t.Run("a row deleted during the import is still reported as not found", func(t *testing.T) {
		svc, _, rows := newImportService(t)
		key := newKey()
		pub, digest := storedPublicKey(t, key)
		rows.rows[digest+"@e1"] = &models.Key{KeyID: digest, EngineID: "e1", Digest: digest, PublicKey: pub}
		rows.recordErr = errs.ErrKeyNotFound
		_, err := svc.ImportKey(ctx, services.ImportKeyInput{PrivateKey: key, EngineID: "e1"})
		require.ErrorIs(t, err, errs.ErrKeyNotFound)
	})
}
