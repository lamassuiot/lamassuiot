package legacy

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/cryptoengines"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/kmip"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeEngine is an in-memory CryptoEngine that names keys like the real ones (SHA-256 of the public key) and
// records the calls it gets.
type fakeEngine struct {
	cryptoengines.CryptoEngine
	keys   map[string]crypto.Signer
	calls  []string
	curves []elliptic.Curve
}

func newFakeEngine() *fakeEngine { return &fakeEngine{keys: map[string]crypto.Signer{}} }

func (e *fakeEngine) GetEngineConfig() models.CryptoEngineInfo {
	return models.CryptoEngineInfo{
		Provider: "fake",
		SupportedKeyTypes: []models.SupportedKeyTypeInfo{
			{Type: models.KeyType(x509.RSA), Sizes: []int{2048, 3072}},
			{Type: models.KeyType(x509.ECDSA), Sizes: []int{256, 384}},
			{Type: models.KeyType(x509.Ed25519), Sizes: []int{256}},
		},
	}
}

func (e *fakeEngine) store(k crypto.Signer) (string, crypto.Signer, error) {
	id, err := helpers.PublicKeyDigest(k.Public())
	if err != nil {
		return "", nil, err
	}
	e.keys[id] = k
	return id, k, nil
}

func (e *fakeEngine) CreateRSAPrivateKey(_ context.Context, bits int) (string, crypto.Signer, error) {
	e.calls = append(e.calls, "CreateRSAPrivateKey")
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return "", nil, err
	}
	return e.store(k)
}

func (e *fakeEngine) CreateECDSAPrivateKey(_ context.Context, curve elliptic.Curve) (string, crypto.Signer, error) {
	e.calls = append(e.calls, "CreateECDSAPrivateKey")
	e.curves = append(e.curves, curve)
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return "", nil, err
	}
	return e.store(k)
}

func (e *fakeEngine) ImportRSAPrivateKey(_ context.Context, k *rsa.PrivateKey) (string, crypto.Signer, error) {
	e.calls = append(e.calls, "ImportRSAPrivateKey")
	return e.store(k)
}

func (e *fakeEngine) ImportECDSAPrivateKey(_ context.Context, k *ecdsa.PrivateKey) (string, crypto.Signer, error) {
	e.calls = append(e.calls, "ImportECDSAPrivateKey")
	return e.store(k)
}

func (e *fakeEngine) GetPrivateKeyByID(_ context.Context, id string) (crypto.Signer, error) {
	e.calls = append(e.calls, "GetPrivateKeyByID")
	if k, ok := e.keys[id]; ok {
		return k, nil
	}
	return nil, errors.New("fake: key not found")
}

func (e *fakeEngine) DeleteKey(_ context.Context, id string) error {
	e.calls = append(e.calls, "DeleteKey")
	if _, ok := e.keys[id]; !ok {
		return errors.New("fake: key not found")
	}
	delete(e.keys, id)
	return nil
}

func TestWrapCapabilities(t *testing.T) {
	caps := Wrap(newFakeEngine()).Capabilities()

	for _, op := range []kmip.Operation{kmip.OpCreateKeyPair, kmip.OpRegister, kmip.OpSign, kmip.OpDestroy} {
		assert.True(t, caps.Supports(op, kmip.RSA, 2048), op.String())
		assert.True(t, caps.Supports(op, kmip.RSA, 3072), op.String())
		assert.True(t, caps.Supports(op, kmip.ECDSA, 256), op.String())
		assert.True(t, caps.Supports(op, kmip.ECDSA, 384), op.String())
	}
	assert.False(t, caps.Supports(kmip.OpCreateKeyPair, kmip.RSA, 4096), "size the engine does not list")
	assert.False(t, caps.Supports(kmip.OpSignatureVerify, kmip.RSA, 2048), "verification is not an engine capability")
	for _, item := range caps.Items {
		assert.NotEqual(t, kmip.CryptographicAlgorithm(0), item.Algorithm, "key types without a KMIP algorithm are skipped")
	}
}

func TestGenerateRSA(t *testing.T) {
	engine := newFakeEngine()
	h, err := Wrap(engine).Generate(context.Background(), cryptoengines.GenerateSpec{ObjectType: kmip.PrivateKey, Algorithm: kmip.RSA, Length: 2048})
	require.NoError(t, err)

	signer, ok := h.(cryptoengines.Signer)
	require.True(t, ok, "a generated private key handle is a Signer")
	wantID, err := helpers.PublicKeyDigest(signer.Public())
	require.NoError(t, err)
	assert.Equal(t, cryptoengines.KeyRef{KeyID: wantID, ObjectType: kmip.PrivateKey, Algorithm: kmip.RSA, Length: 2048}, h.Ref())
	assert.Equal(t, engine.keys[wantID].Public(), signer.Public())
	assert.Equal(t, []string{"CreateRSAPrivateKey"}, engine.calls)
}

func TestGenerateECDSACurves(t *testing.T) {
	for length, curve := range map[int]elliptic.Curve{224: elliptic.P224(), 256: elliptic.P256(), 384: elliptic.P384(), 521: elliptic.P521()} {
		engine := newFakeEngine()
		h, err := Wrap(engine).Generate(context.Background(), cryptoengines.GenerateSpec{ObjectType: kmip.PrivateKey, Algorithm: kmip.ECDSA, Length: length})
		require.NoError(t, err, length)
		assert.Equal(t, []elliptic.Curve{curve}, engine.curves, length)
		assert.Equal(t, length, h.Ref().Length)
		assert.Equal(t, kmip.ECDSA, h.Ref().Algorithm)
	}
}

func TestGenerateECDSAInvalidSize(t *testing.T) {
	engine := newFakeEngine()
	_, err := Wrap(engine).Generate(context.Background(), cryptoengines.GenerateSpec{ObjectType: kmip.PrivateKey, Algorithm: kmip.ECDSA, Length: 300})
	assert.ErrorIs(t, err, ErrInvalidECDSASize)
	assert.EqualError(t, err, "invalid ECDSA key size")
	assert.Empty(t, engine.calls)
}

func TestGenerateRejectsWhatLegacyEnginesCannotDo(t *testing.T) {
	specs := map[string]cryptoengines.GenerateSpec{
		"a key id chosen by the KMS": {ObjectType: kmip.PrivateKey, Algorithm: kmip.RSA, Length: 2048, KeyID: "chosen"},
		"a symmetric key":            {ObjectType: kmip.SymmetricKey, Algorithm: kmip.AES, Length: 256},
		"a public key":               {ObjectType: kmip.PublicKey, Algorithm: kmip.RSA, Length: 2048},
		"an unknown algorithm":       {ObjectType: kmip.PrivateKey, Algorithm: kmip.AES, Length: 256},
	}
	for name, spec := range specs {
		engine := newFakeEngine()
		_, err := Wrap(engine).Generate(context.Background(), spec)
		assert.ErrorIs(t, err, ErrUnsupported, name)
		assert.EqualError(t, err, "unknown or unsupported algorithm", name)
		assert.Empty(t, engine.calls, name)
	}
}

func TestImportRSAAndECDSA(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	cases := []struct {
		key    crypto.Signer
		alg    kmip.CryptographicAlgorithm
		length int
		call   string
	}{
		{rsaKey, kmip.RSA, 2048, "ImportRSAPrivateKey"},
		{ecKey, kmip.ECDSA, 384, "ImportECDSAPrivateKey"},
	}
	for _, c := range cases {
		engine := newFakeEngine()
		h, err := Wrap(engine).Import(context.Background(), cryptoengines.ImportSpec{ObjectType: kmip.PrivateKey, Private: c.key})
		require.NoError(t, err)
		wantID, err := helpers.PublicKeyDigest(c.key.Public())
		require.NoError(t, err)
		assert.Equal(t, cryptoengines.KeyRef{KeyID: wantID, ObjectType: kmip.PrivateKey, Algorithm: c.alg, Length: c.length}, h.Ref())
		assert.Equal(t, []string{c.call}, engine.calls)
	}
}

func TestImportUnsupportedKeyType(t *testing.T) {
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	engine := newFakeEngine()

	_, err = Wrap(engine).Import(context.Background(), cryptoengines.ImportSpec{ObjectType: kmip.PrivateKey, Private: edKey})
	assert.ErrorIs(t, err, ErrUnsupportedKeyType)
	assert.EqualError(t, err, "unsupported private key type")

	_, err = Wrap(engine).Import(context.Background(), cryptoengines.ImportSpec{ObjectType: kmip.PrivateKey, KeyID: "chosen", Private: edKey})
	assert.ErrorIs(t, err, ErrUnsupported)
	assert.Empty(t, engine.calls)
}

func TestLoadAndSign(t *testing.T) {
	engine := newFakeEngine()
	b := Wrap(engine)
	created, err := b.Generate(context.Background(), cryptoengines.GenerateSpec{ObjectType: kmip.PrivateKey, Algorithm: kmip.ECDSA, Length: 256})
	require.NoError(t, err)

	h, err := b.Load(context.Background(), created.Ref())
	require.NoError(t, err)
	assert.Equal(t, created.Ref(), h.Ref())
	signer, ok := h.(cryptoengines.Signer)
	require.True(t, ok)

	digest := sha256.Sum256([]byte("message"))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)
	assert.True(t, ecdsa.VerifyASN1(signer.Public().(*ecdsa.PublicKey), digest[:], sig))
}

func TestLoadUnknown(t *testing.T) {
	_, err := Wrap(newFakeEngine()).Load(context.Background(), cryptoengines.KeyRef{KeyID: "missing", ObjectType: kmip.PrivateKey, Algorithm: kmip.RSA, Length: 2048})
	assert.EqualError(t, err, "fake: key not found")
}

// A CryptoEngine only holds private keys, named after the SHA-256 of the public key, which also names the public
// half of the pair. A reference to anything but the private key must not reach the engine: it would load or
// delete the private key.
func TestLoadAndDestroyOnlyPrivateKeys(t *testing.T) {
	engine := newFakeEngine()
	b := Wrap(engine)
	created, err := b.Generate(context.Background(), cryptoengines.GenerateSpec{ObjectType: kmip.PrivateKey, Algorithm: kmip.ECDSA, Length: 256})
	require.NoError(t, err)
	engine.calls = nil

	for _, objectType := range []kmip.ObjectType{kmip.PublicKey, kmip.SymmetricKey, 0} {
		ref := created.Ref()
		ref.ObjectType = objectType

		_, err := b.Load(context.Background(), ref)
		assert.ErrorIs(t, err, ErrUnsupported, objectType.String())
		assert.ErrorIs(t, b.Destroy(context.Background(), ref), ErrUnsupported, objectType.String())
	}
	assert.Empty(t, engine.calls)
	assert.Contains(t, engine.keys, created.Ref().KeyID, "the private key is still there")
}

// An engine returning no signer and no error is an error, not a handle that panics when used.
func TestLoadNilSigner(t *testing.T) {
	engine := &nilSignerEngine{newFakeEngine()}
	_, err := Wrap(engine).Load(context.Background(), cryptoengines.KeyRef{KeyID: "any", ObjectType: kmip.PrivateKey, Algorithm: kmip.RSA, Length: 2048})
	assert.Error(t, err)
}

type nilSignerEngine struct{ *fakeEngine }

func (e *nilSignerEngine) GetPrivateKeyByID(context.Context, string) (crypto.Signer, error) {
	return nil, nil
}

func TestDestroy(t *testing.T) {
	engine := newFakeEngine()
	b := Wrap(engine)
	created, err := b.Generate(context.Background(), cryptoengines.GenerateSpec{ObjectType: kmip.PrivateKey, Algorithm: kmip.ECDSA, Length: 256})
	require.NoError(t, err)

	require.NoError(t, b.Destroy(context.Background(), created.Ref()))
	_, err = b.Load(context.Background(), created.Ref())
	assert.Error(t, err)
}
