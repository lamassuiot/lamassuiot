package services

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"io"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/cryptoengines"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/kmip"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// kmsRows extends keyRows with the operations create, import, lookup and delete use.
type kmsRows struct {
	keyRows
}

func (s *kmsRows) Insert(_ context.Context, key *models.Key) (*models.Key, error) {
	s.keys[key.KeyID+"@"+key.EngineID] = key
	return key, nil
}

func (s *kmsRows) SelectByKeyID(_ context.Context, keyID string) ([]*models.Key, error) {
	copies := []*models.Key{}
	for _, key := range s.keys {
		if key.KeyID == keyID {
			copies = append(copies, key)
		}
	}
	return copies, nil
}

func (s *kmsRows) DeleteWith(_ context.Context, keyID, engineID string, fn func() error) error {
	if err := fn(); err != nil {
		return err
	}
	delete(s.keys, keyID+"@"+engineID)
	return nil
}

// spyBackendEngine is a CryptoEngine that also implements Backend natively. It records the Backend calls it
// gets and holds software keys named after the SHA-256 of their public key.
type spyBackendEngine struct {
	cryptoengines.CryptoEngine
	keys  map[string]crypto.Signer
	calls []string
	loads []cryptoengines.KeyRef
}

type spyHandle struct {
	ref cryptoengines.KeyRef
	crypto.Signer
}

func (h *spyHandle) Ref() cryptoengines.KeyRef { return h.ref }

func newSpyBackendEngine() *spyBackendEngine {
	return &spyBackendEngine{keys: map[string]crypto.Signer{}}
}

func (e *spyBackendEngine) GetEngineConfig() models.CryptoEngineInfo {
	return models.CryptoEngineInfo{Provider: "spy", Type: models.Golang}
}

func (e *spyBackendEngine) Capabilities() cryptoengines.Capabilities {
	caps := cryptoengines.Capabilities{}
	for _, op := range []kmip.Operation{kmip.OpCreateKeyPair, kmip.OpRegister, kmip.OpSign, kmip.OpDestroy} {
		caps.Items = append(caps.Items,
			cryptoengines.Capability{Operation: op, Algorithm: kmip.RSA, Lengths: []int{2048}},
			cryptoengines.Capability{Operation: op, Algorithm: kmip.ECDSA, Lengths: []int{256}})
	}
	return caps
}

func (e *spyBackendEngine) hold(t kmip.CryptographicAlgorithm, length int, k crypto.Signer) cryptoengines.KeyHandle {
	der, _ := x509.MarshalPKIXPublicKey(k.Public())
	sum := sha256.Sum256(der)
	id := ""
	for _, b := range sum {
		id += string("0123456789abcdef"[b>>4]) + string("0123456789abcdef"[b&0xf])
	}
	e.keys[id] = k
	return &spyHandle{ref: cryptoengines.KeyRef{KeyID: id, ObjectType: kmip.PrivateKey, Algorithm: t, Length: length}, Signer: k}
}

func (e *spyBackendEngine) Generate(_ context.Context, spec cryptoengines.GenerateSpec) (cryptoengines.KeyHandle, error) {
	e.calls = append(e.calls, "Generate")
	if spec.Algorithm == kmip.RSA {
		k, err := rsa.GenerateKey(rand.Reader, spec.Length)
		if err != nil {
			return nil, err
		}
		return e.hold(kmip.RSA, spec.Length, k), nil
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return e.hold(kmip.ECDSA, 256, k), nil
}

func (e *spyBackendEngine) Import(_ context.Context, spec cryptoengines.ImportSpec) (cryptoengines.KeyHandle, error) {
	e.calls = append(e.calls, "Import")
	k := spec.Private.(*ecdsa.PrivateKey)
	return e.hold(kmip.ECDSA, 256, k), nil
}

func (e *spyBackendEngine) Load(_ context.Context, ref cryptoengines.KeyRef) (cryptoengines.KeyHandle, error) {
	e.calls = append(e.calls, "Load")
	e.loads = append(e.loads, ref)
	k, ok := e.keys[ref.KeyID]
	if !ok {
		return nil, io.EOF
	}
	return &spyHandle{ref: ref, Signer: k}, nil
}

func (e *spyBackendEngine) Destroy(_ context.Context, ref cryptoengines.KeyRef) error {
	e.calls = append(e.calls, "Destroy")
	delete(e.keys, ref.KeyID)
	return nil
}

var _ cryptoengines.Backend = (*spyBackendEngine)(nil)

func newTestKMS(t *testing.T, engineID string, engine cryptoengines.CryptoEngine) (services.KMSService, *kmsRows) {
	t.Helper()
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	rows := &kmsRows{keyRows{keys: map[string]*models.Key{}}}
	svc, err := NewKMSService(KMSServiceBuilder{
		Logger:        logrus.NewEntry(logger),
		CryptoEngines: map[string]*Engine{engineID: {Default: true, Service: engine}},
		KMSStorage:    rows,
	})
	require.NoError(t, err)
	return svc, rows
}

func TestCreateKeyGoesThroughBackend(t *testing.T) {
	engine := newSpyBackendEngine()
	svc, _ := newTestKMS(t, "spy-1", engine)

	key, err := svc.CreateKey(context.Background(), services.CreateKeyInput{Algorithm: "RSA", Size: 2048, Name: "k"})
	require.NoError(t, err)

	assert.Equal(t, []string{"Generate"}, engine.calls)
	require.Contains(t, engine.keys, key.KeyID)
	pub := parsePublicKeyForTest(t, key.PublicKey)
	assert.True(t, engine.keys[key.KeyID].Public().(*rsa.PublicKey).Equal(pub))
	assert.Equal(t, "spy-1", key.EngineID)
	assert.True(t, key.HasPrivateKey)
}

func TestCreateKeyRejectsUnsupportedSize(t *testing.T) {
	engine := newSpyBackendEngine()
	svc, _ := newTestKMS(t, "spy-1", engine)

	_, err := svc.CreateKey(context.Background(), services.CreateKeyInput{Algorithm: "RSA", Size: 1024, Name: "k"})
	assert.EqualError(t, err, "key size 1024 is not supported for key type RSA in engine spy")
	_, err = svc.CreateKey(context.Background(), services.CreateKeyInput{Algorithm: "Ed25519", Size: 256, Name: "k"})
	assert.EqualError(t, err, "key type Ed25519 is not supported in engine spy")
	assert.Empty(t, engine.calls)
}

func TestImportKeyGoesThroughBackend(t *testing.T) {
	engine := newSpyBackendEngine()
	svc, _ := newTestKMS(t, "spy-1", engine)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	key, err := svc.ImportKey(context.Background(), services.ImportKeyInput{PrivateKey: priv, Name: "k"})
	require.NoError(t, err)

	assert.Equal(t, []string{"Import"}, engine.calls)
	assert.Equal(t, "ECDSA", key.Algorithm)
	assert.Equal(t, 256, key.Size)
	assert.True(t, priv.PublicKey.Equal(parsePublicKeyForTest(t, key.PublicKey)))
}

func TestDeleteKeyGoesThroughBackend(t *testing.T) {
	engine := newSpyBackendEngine()
	svc, rows := newTestKMS(t, "spy-1", engine)
	key, err := svc.CreateKey(context.Background(), services.CreateKeyInput{Algorithm: "ECDSA", Size: 256, Name: "k"})
	require.NoError(t, err)
	engine.calls = nil

	require.NoError(t, svc.DeleteKeyByID(context.Background(), services.GetKeyInput{Identifier: key.KeyID}))

	assert.Equal(t, []string{"Load", "Destroy"}, engine.calls)
	assert.NotContains(t, engine.keys, key.KeyID)
	assert.Empty(t, rows.keys)
}

func TestSignMessageGoesThroughBackend(t *testing.T) {
	engine := newSpyBackendEngine()
	svc, _ := newTestKMS(t, "spy-1", engine)
	key, err := svc.CreateKey(context.Background(), services.CreateKeyInput{Algorithm: "ECDSA", Size: 256, Name: "k"})
	require.NoError(t, err)

	sig, err := svc.SignMessage(context.Background(), services.SignMessageInput{Identifier: key.KeyID, Algorithm: "ECDSA_SHA_256", Message: []byte("lamassu"), MessageType: models.Raw})
	require.NoError(t, err)

	require.Len(t, engine.loads, 1)
	assert.Equal(t, cryptoengines.KeyRef{KeyID: key.KeyID, ObjectType: kmip.PrivateKey, Algorithm: kmip.ECDSA, Length: 256}, engine.loads[0])
	digest := sha256.Sum256([]byte("lamassu"))
	assert.True(t, ecdsa.VerifyASN1(parsePublicKeyForTest(t, key.PublicKey).(*ecdsa.PublicKey), digest[:], sig.Signature))
}

// A CryptoEngine without a native Backend is wrapped by the legacy adapter: signing reaches GetPrivateKeyByID.
func TestSignMessageThroughWrappedCryptoEngine(t *testing.T) {
	signer, publicKey, keyID := newNamedKey(t)
	engine := &namedKeysEngine{keys: map[string]crypto.Signer{keyID: signer}}
	svc, rows := newTestKMS(t, "named-1", engine)
	rows.keys[keyID+"@named-1"] = &models.Key{KeyID: keyID, EngineID: "named-1", Algorithm: "ECDSA", Size: 256, PublicKey: publicKey, HasPrivateKey: true}

	sig, err := svc.SignMessage(context.Background(), services.SignMessageInput{Identifier: keyID, Algorithm: "ECDSA_SHA_256", Message: []byte("lamassu"), MessageType: models.Raw})
	require.NoError(t, err)

	digest := sha256.Sum256([]byte("lamassu"))
	assert.True(t, ecdsa.VerifyASN1(signer.Public().(*ecdsa.PublicKey), digest[:], sig.Signature))
}

func TestSignMessageKeyNotInEngine(t *testing.T) {
	_, publicKey, keyID := newNamedKey(t)
	engine := &namedKeysEngine{keys: map[string]crypto.Signer{}}
	svc, rows := newTestKMS(t, "named-1", engine)
	rows.keys[keyID+"@named-1"] = &models.Key{KeyID: keyID, EngineID: "named-1", Algorithm: "ECDSA", Size: 256, PublicKey: publicKey, HasPrivateKey: true}

	_, err := svc.SignMessage(context.Background(), services.SignMessageInput{Identifier: keyID, Algorithm: "ECDSA_SHA_256", Message: []byte("lamassu"), MessageType: models.Raw})
	assert.EqualError(t, err, "could not get signing key")
}

// D1: verification uses the stored public key, so a public-only key, which no engine holds, verifies.
func TestVerifySignaturePublicOnlyKey(t *testing.T) {
	signer, publicKey, keyID := newNamedKey(t)
	engine := newSpyBackendEngine()
	svc, rows := newTestKMS(t, "spy-1", engine)
	rows.keys[keyID+"@spy-1"] = &models.Key{KeyID: keyID, EngineID: "spy-1", Algorithm: "ECDSA", Size: 256, PublicKey: publicKey, HasPrivateKey: false}

	digest := sha256.Sum256([]byte("lamassu"))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)

	res, err := svc.VerifySignature(context.Background(), services.VerifySignInput{Identifier: keyID, Algorithm: "ECDSA_SHA_256", Signature: sig, Message: []byte("lamassu"), MessageType: models.Raw})
	require.NoError(t, err)
	assert.True(t, res.Valid)

	res, err = svc.VerifySignature(context.Background(), services.VerifySignInput{Identifier: keyID, Algorithm: "ECDSA_SHA_256", Signature: sig, Message: []byte("tampered"), MessageType: models.Raw})
	require.NoError(t, err)
	assert.False(t, res.Valid)
	assert.Empty(t, engine.calls, "verification does not reach the engine")
}

func TestVerifySignatureBadStoredPublicKey(t *testing.T) {
	svc, rows := newTestKMS(t, "spy-1", newSpyBackendEngine())
	rows.keys["bad@spy-1"] = &models.Key{KeyID: "bad", EngineID: "spy-1", Algorithm: "ECDSA", Size: 256, PublicKey: "!!", HasPrivateKey: true}

	_, err := svc.VerifySignature(context.Background(), services.VerifySignInput{Identifier: "bad", Algorithm: "ECDSA_SHA_256", Signature: []byte{1}, Message: []byte("m"), MessageType: models.Raw})
	assert.Error(t, err)
}

func TestVerifySignatureAlgorithmMismatch(t *testing.T) {
	_, publicKey, keyID := newNamedKey(t)
	svc, rows := newTestKMS(t, "spy-1", newSpyBackendEngine())
	rows.keys[keyID+"@spy-1"] = &models.Key{KeyID: keyID, EngineID: "spy-1", Algorithm: "ECDSA", Size: 256, PublicKey: publicKey, HasPrivateKey: true}

	_, err := svc.VerifySignature(context.Background(), services.VerifySignInput{Identifier: keyID, Algorithm: "RSASSA_PSS_SHA_256", Signature: []byte{1}, Message: []byte("m"), MessageType: models.Raw})
	assert.EqualError(t, err, "key is not RSA key")
}

func parsePublicKeyForTest(t *testing.T, stored string) crypto.PublicKey {
	t.Helper()
	pub, err := parseStoredPublicKey(stored)
	require.NoError(t, err)
	return pub
}
