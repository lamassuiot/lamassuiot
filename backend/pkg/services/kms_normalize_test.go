package services

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/cryptoengines"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// namedKeysEngine holds keys by name. Only the operations key name normalization uses are implemented.
type namedKeysEngine struct {
	cryptoengines.CryptoEngine
	keys      map[string]crypto.Signer
	renameErr error
	renamed   []string
}

func (e *namedKeysEngine) GetPrivateKeyByID(_ context.Context, name string) (crypto.Signer, error) {
	if key, ok := e.keys[name]; ok {
		return key, nil
	}
	return nil, errors.New("key not found")
}

func (e *namedKeysEngine) RenameKey(_ context.Context, oldName, newName string) error {
	if e.renameErr != nil {
		return e.renameErr
	}
	e.keys[newName] = e.keys[oldName]
	delete(e.keys, oldName)
	e.renamed = append(e.renamed, oldName+" -> "+newName)
	return nil
}

// keyRows keeps key rows by (key_id, engine_id). Only the operations key name normalization uses are
// implemented.
type keyRows struct {
	storage.KMSKeysRepo
	keys map[string]*models.Key
}

func (s *keyRows) SelectAll(_ context.Context, req storage.StorageListRequest[models.Key]) (string, error) {
	for _, key := range s.keys {
		req.ApplyFunc(*key)
	}
	return "", nil
}

func (s *keyRows) SelectExistsByKeyID(_ context.Context, keyID, engineID string) (bool, *models.Key, error) {
	key, ok := s.keys[keyID+"@"+engineID]
	return ok, key, nil
}

func (s *keyRows) RenameKey(_ context.Context, engineID, oldKeyID, newKeyID string, renameInEngine func() error) (bool, error) {
	key, ok := s.keys[oldKeyID+"@"+engineID]
	if !ok {
		return false, nil
	}
	if err := renameInEngine(); err != nil {
		return false, err
	}
	delete(s.keys, oldKeyID+"@"+engineID)
	key.KeyID = newKeyID
	key.Aliases = append(key.Aliases, oldKeyID)
	s.keys[newKeyID+"@"+engineID] = key
	return true, nil
}

// newNamedKey returns a key pair, its public key as the KMS stores it, and the SHA-256 of its
// SubjectPublicKeyInfo.
func newNamedKey(t *testing.T) (crypto.Signer, string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	digest := sha256.Sum256(spki)
	return key, base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki})), hex.EncodeToString(digest[:])
}

// Keys that crypto engines hold under another name, such as the keys of CAs imported before the KMS,
// renamed to their certificate's SKI, are renamed to their digest in the engine and in the KMS.
func TestNormalizeKeyNames(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	ctx := context.Background()

	row := func(keyID, engineID, publicKey string, hasPrivateKey bool) *models.Key {
		return &models.Key{KeyID: keyID, EngineID: engineID, PublicKey: publicKey, HasPrivateKey: hasPrivateKey, Aliases: []string{}}
	}

	t.Run("a key held under its SKI takes its digest as key_id and keeps the SKI as alias", func(t *testing.T) {
		signer, publicKey, digest := newNamedKey(t)
		engine := &namedKeysEngine{keys: map[string]crypto.Signer{"ski": signer}}
		rows := &keyRows{keys: map[string]*models.Key{"ski@e": row("ski", "e", publicKey, true)}}

		require.Equal(t, 1, NormalizeKeyNames(ctx, logrus.NewEntry(logger), rows, map[string]*Engine{"e": {Service: engine}}))
		require.Equal(t, []string{"ski -> " + digest}, engine.renamed)
		require.Contains(t, rows.keys, digest+"@e")
		require.Equal(t, []string{"ski"}, rows.keys[digest+"@e"].Aliases)
	})

	t.Run("a key the engine already renamed only has its row renamed", func(t *testing.T) {
		signer, publicKey, digest := newNamedKey(t)
		engine := &namedKeysEngine{keys: map[string]crypto.Signer{digest: signer}}
		rows := &keyRows{keys: map[string]*models.Key{"ski@e": row("ski", "e", publicKey, true)}}

		require.Equal(t, 1, NormalizeKeyNames(ctx, logrus.NewEntry(logger), rows, map[string]*Engine{"e": {Service: engine}}))
		require.Empty(t, engine.renamed)
		require.Contains(t, rows.keys, digest+"@e")
	})

	t.Run("keys that need no rename, or cannot be renamed safely, are left as they are", func(t *testing.T) {
		named, namedPub, namedDigest := newNamedKey(t)
		twice, twicePub, twiceDigest := newNamedKey(t)
		_, publicOnlyPub, _ := newNamedKey(t)
		other, otherPub, _ := newNamedKey(t)
		engine := &namedKeysEngine{keys: map[string]crypto.Signer{namedDigest: named, "twice-ski": twice, twiceDigest: twice, "other-ski": other}}
		rows := &keyRows{keys: map[string]*models.Key{
			namedDigest + "@e":  row(namedDigest, "e", namedPub, true),         // already named by its digest
			"twice-ski@e":       row("twice-ski", "e", twicePub, true),         // also registered under its digest
			twiceDigest + "@e":  row(twiceDigest, "e", twicePub, true),         //
			"public-only@e":     row("public-only", "e", publicOnlyPub, false), // no private key in the engine
			"other-ski@missing": row("other-ski", "missing", otherPub, true),   // engine not configured
			"unreadable@e":      row("unreadable", "e", "pub", true),           // public key cannot be read
		}}

		require.Equal(t, 0, NormalizeKeyNames(ctx, logrus.NewEntry(logger), rows, map[string]*Engine{"e": {Service: engine}}))
		require.Empty(t, engine.renamed)
		require.Len(t, rows.keys, 6)
	})

	t.Run("a key that fails to rename does not stop the others", func(t *testing.T) {
		first, firstPub, _ := newNamedKey(t)
		second, secondPub, secondDigest := newNamedKey(t)
		failing := &namedKeysEngine{keys: map[string]crypto.Signer{"first-ski": first}, renameErr: errors.New("engine unavailable")}
		working := &namedKeysEngine{keys: map[string]crypto.Signer{"second-ski": second}}
		rows := &keyRows{keys: map[string]*models.Key{
			"first-ski@failing":  row("first-ski", "failing", firstPub, true),
			"second-ski@working": row("second-ski", "working", secondPub, true),
		}}

		require.Equal(t, 1, NormalizeKeyNames(ctx, logrus.NewEntry(logger), rows, map[string]*Engine{"failing": {Service: failing}, "working": {Service: working}}))
		require.Contains(t, rows.keys, "first-ski@failing", "the failed key keeps its name until the next run")
		require.Contains(t, rows.keys, secondDigest+"@working")
	})
}
