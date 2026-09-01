package softwarev2_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"testing"

	cryptoenginesv2 "github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines_v2"
	softwarev2 "github.com/lamassuiot/lamassuiot/engines/crypto/softwarev2/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gocloud.dev/blob/memblob"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func newTestBackend(t *testing.T) *softwarev2.Backend {
	t.Helper()
	bucket := memblob.OpenBucket(nil)
	t.Cleanup(func() { _ = bucket.Close() })
	b, err := softwarev2.New(softwarev2.Options{Blobs: bucket})
	require.NoError(t, err)
	return b
}

var keySeq int

func generateKey(t *testing.T, b *softwarev2.Backend, spec cryptoenginesv2.KeySpec) cryptoenginesv2.KeyHandle {
	t.Helper()
	keySeq++
	h, err := b.Generate(context.Background(), cryptoenginesv2.CreateKeySpec{
		KeyID:   cryptoenginesv2.KeyID(fmt.Sprintf("key-%d-%s", keySeq, spec)),
		KeySpec: spec,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = h.Close() })
	return h
}

// ecdhPubOf returns an *ecdh.PublicKey for a handle regardless of whether its
// stored public key is an EC (ecdsa) or a native X25519 key.
func ecdhPubOf(t *testing.T, h cryptoenginesv2.KeyHandle) *ecdh.PublicKey {
	t.Helper()
	switch p := h.Metadata().PublicKey.(type) {
	case *ecdh.PublicKey:
		return p
	case *ecdsa.PublicKey:
		e, err := p.ECDH()
		require.NoError(t, err)
		return e
	}
	t.Fatalf("unexpected public key type %T", h.Metadata().PublicKey)
	return nil
}

// ---------------------------------------------------------------------------
// Key reuse — the AWS-KMS model: one key, many per-operation algorithms.
// ---------------------------------------------------------------------------

func TestKeyReuse_RSA_OneKeyManyAlgorithms(t *testing.T) {
	b := newTestBackend(t)
	h := generateKey(t, b, cryptoenginesv2.KeySpecRSA2048)
	pub := h.(cryptoenginesv2.Signer).Public().(*rsa.PublicKey)
	ctx := context.Background()

	// PKCS#1 v1.5 with SHA-256.
	d256 := sha256.Sum256([]byte("m"))
	sig, err := h.(cryptoenginesv2.Signer).SignContext(ctx, d256[:], cryptoenginesv2.AlgRSASSAPKCS1V15SHA256, crypto.SHA256)
	require.NoError(t, err)
	require.NoError(t, rsa.VerifyPKCS1v15(pub, crypto.SHA256, d256[:], sig))

	// PSS with SHA-512 — SAME key, different scheme AND hash.
	d512 := sha512.Sum512([]byte("m"))
	sig, err = h.(cryptoenginesv2.Signer).SignContext(ctx, d512[:], cryptoenginesv2.AlgRSASSAPSSSHA512, crypto.SHA512)
	require.NoError(t, err)
	require.NoError(t, rsa.VerifyPSS(pub, crypto.SHA512, d512[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA512}))

	// OAEP decrypt — SAME key, encryption algorithm.
	plaintext := []byte("secret")
	ct, err := h.(cryptoenginesv2.Encrypter).EncryptContext(ctx, plaintext, cryptoenginesv2.AlgRSAESOAEPSHA256, cryptoenginesv2.EncryptOpts{Hash: crypto.SHA256})
	require.NoError(t, err)
	got, err := h.(cryptoenginesv2.Decrypter).DecryptContext(ctx, ct, cryptoenginesv2.AlgRSAESOAEPSHA256, &rsa.OAEPOptions{Hash: crypto.SHA256})
	require.NoError(t, err)
	assert.Equal(t, plaintext, got)
}

func TestKeyReuse_EC_SignAndAgree(t *testing.T) {
	b := newTestBackend(t)
	h := generateKey(t, b, cryptoenginesv2.KeySpecECCNISTP256)
	ctx := context.Background()

	// ECDSA sign on the EC key.
	pub := h.Metadata().PublicKey.(*ecdsa.PublicKey)
	digest := sha256.Sum256([]byte("m"))
	sig, err := h.(cryptoenginesv2.Signer).SignContext(ctx, digest[:], cryptoenginesv2.AlgECDSASHA256, nil)
	require.NoError(t, err)
	assert.True(t, ecdsa.VerifyASN1(pub, digest[:], sig))

	// ECDH agree on the SAME EC key.
	peer, err := ecdh.P256().GenerateKey(nil)
	require.NoError(t, err)
	shared, err := h.(cryptoenginesv2.KeyAgreementer).Agree(ctx, peer.PublicKey(), cryptoenginesv2.AlgECDH)
	require.NoError(t, err)
	peerShared, err := peer.ECDH(ecdhPubOf(t, h))
	require.NoError(t, err)
	assert.Equal(t, peerShared, shared)
}

func TestRSA_RejectsIncompatibleAlgorithm(t *testing.T) {
	b := newTestBackend(t)
	h := generateKey(t, b, cryptoenginesv2.KeySpecRSA2048)
	digest := sha256.Sum256([]byte("m"))
	_, err := h.(cryptoenginesv2.Signer).SignContext(context.Background(), digest[:], cryptoenginesv2.AlgECDSASHA256, crypto.SHA256)
	assert.Error(t, err, "RSA handle must reject a non-RSA signing algorithm")
}

// ---------------------------------------------------------------------------
// AES-GCM
// ---------------------------------------------------------------------------

func TestAES_GCM_Roundtrip(t *testing.T) {
	for _, spec := range []cryptoenginesv2.KeySpec{
		cryptoenginesv2.KeySpecAES128,
		cryptoenginesv2.KeySpecAES192,
		cryptoenginesv2.KeySpecSymmetricDefault,
	} {
		spec := spec
		t.Run(string(spec), func(t *testing.T) {
			b := newTestBackend(t)
			h := generateKey(t, b, spec)

			cipher, ok := h.(cryptoenginesv2.SymmetricCipher)
			require.True(t, ok, "handle must implement SymmetricCipher")

			plaintext := []byte("the quick brown fox jumps over the lazy dog")
			ctx := context.Background()

			ct, err := cipher.Encrypt(ctx, plaintext, cryptoenginesv2.AlgSymmetricDefault, cryptoenginesv2.SymmetricOpts{})
			require.NoError(t, err)
			assert.NotEmpty(t, ct.Bytes)
			assert.NotEmpty(t, ct.Nonce)
			assert.NotEqual(t, plaintext, ct.Bytes)

			got, err := cipher.Decrypt(ctx, ct, cryptoenginesv2.SymmetricOpts{})
			require.NoError(t, err)
			assert.Equal(t, plaintext, got)
		})
	}
}

func TestAES_GCM_WithAssociatedData(t *testing.T) {
	b := newTestBackend(t)
	h := generateKey(t, b, cryptoenginesv2.KeySpecSymmetricDefault)
	cipher := h.(cryptoenginesv2.SymmetricCipher)

	plaintext := []byte("secret message")
	aad := []byte("associated-data-header")
	ctx := context.Background()

	ct, err := cipher.Encrypt(ctx, plaintext, cryptoenginesv2.AlgSymmetricDefault, cryptoenginesv2.SymmetricOpts{AssociatedData: aad})
	require.NoError(t, err)

	// Correct AAD → decryption succeeds.
	got, err := cipher.Decrypt(ctx, ct, cryptoenginesv2.SymmetricOpts{AssociatedData: aad})
	require.NoError(t, err)
	assert.Equal(t, plaintext, got)

	// Wrong AAD → decryption fails (authentication tag mismatch).
	_, err = cipher.Decrypt(ctx, ct, cryptoenginesv2.SymmetricOpts{AssociatedData: []byte("wrong")})
	assert.Error(t, err)
}

func TestAES_GCM_TamperedCiphertext(t *testing.T) {
	b := newTestBackend(t)
	h := generateKey(t, b, cryptoenginesv2.KeySpecSymmetricDefault)
	cipher := h.(cryptoenginesv2.SymmetricCipher)

	ct, err := cipher.Encrypt(context.Background(), []byte("hello"), cryptoenginesv2.AlgSymmetricDefault, cryptoenginesv2.SymmetricOpts{})
	require.NoError(t, err)

	// Flip a byte in the ciphertext.
	tampered := cryptoenginesv2.Ciphertext{
		Algorithm: ct.Algorithm,
		Nonce:     ct.Nonce,
		Bytes:     append([]byte(nil), ct.Bytes...),
		AAD:       ct.AAD,
	}
	tampered.Bytes[0] ^= 0xFF

	_, err = cipher.Decrypt(context.Background(), tampered, cryptoenginesv2.SymmetricOpts{})
	assert.Error(t, err, "tampered ciphertext must not decrypt")
}

// ---------------------------------------------------------------------------
// ECDSA
// ---------------------------------------------------------------------------

func TestECDSA_SignVerify(t *testing.T) {
	cases := []struct {
		spec cryptoenginesv2.KeySpec
		alg  cryptoenginesv2.AlgorithmID
		hash crypto.Hash
	}{
		{cryptoenginesv2.KeySpecECCNISTP256, cryptoenginesv2.AlgECDSASHA256, crypto.SHA256},
		{cryptoenginesv2.KeySpecECCNISTP384, cryptoenginesv2.AlgECDSASHA384, crypto.SHA384},
		{cryptoenginesv2.KeySpecECCNISTP521, cryptoenginesv2.AlgECDSASHA512, crypto.SHA512},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(string(tc.spec), func(t *testing.T) {
			b := newTestBackend(t)
			h := generateKey(t, b, tc.spec)

			signer, ok := h.(cryptoenginesv2.Signer)
			require.True(t, ok, "handle must implement Signer")

			pub, ok := signer.Public().(*ecdsa.PublicKey)
			require.True(t, ok)

			message := []byte("sign me")
			digest := hashMessage(tc.hash, message)

			sig, err := signer.SignContext(context.Background(), digest, tc.alg, tc.hash)
			require.NoError(t, err)
			assert.NotEmpty(t, sig)

			assert.True(t, ecdsa.VerifyASN1(pub, digest, sig), "signature must verify")

			// Wrong digest → invalid signature.
			badDigest := hashMessage(tc.hash, []byte("different"))
			assert.False(t, ecdsa.VerifyASN1(pub, badDigest, sig), "must not verify with wrong digest")
		})
	}
}

// ---------------------------------------------------------------------------
// ECDH
// ---------------------------------------------------------------------------

func TestECDH_KeyAgreement(t *testing.T) {
	for _, spec := range []cryptoenginesv2.KeySpec{
		cryptoenginesv2.KeySpecECCNISTP256,
		cryptoenginesv2.KeySpecECCNISTP384,
		cryptoenginesv2.KeySpecECCNISTP521,
		cryptoenginesv2.KeySpecX25519,
	} {
		spec := spec
		t.Run(string(spec), func(t *testing.T) {
			b := newTestBackend(t)
			h1 := generateKey(t, b, spec)
			h2 := generateKey(t, b, spec)

			ka1, ok := h1.(cryptoenginesv2.KeyAgreementer)
			require.True(t, ok, "h1 must implement KeyAgreementer")
			ka2, ok := h2.(cryptoenginesv2.KeyAgreementer)
			require.True(t, ok, "h2 must implement KeyAgreementer")

			ctx := context.Background()

			ss1, err := ka1.Agree(ctx, ecdhPubOf(t, h2), cryptoenginesv2.AlgECDH)
			require.NoError(t, err)

			ss2, err := ka2.Agree(ctx, ecdhPubOf(t, h1), cryptoenginesv2.AlgECDH)
			require.NoError(t, err)

			assert.Equal(t, ss1, ss2, "both parties must derive the same shared secret")
			assert.NotEmpty(t, ss1)
		})
	}
}

// ---------------------------------------------------------------------------
// RSA signing — one RSA_2048 key exercised across every hash and scheme.
// ---------------------------------------------------------------------------

func TestRSA_PKCS1v15_SignVerify(t *testing.T) {
	cases := []struct {
		alg  cryptoenginesv2.AlgorithmID
		hash crypto.Hash
	}{
		{cryptoenginesv2.AlgRSASSAPKCS1V15SHA256, crypto.SHA256},
		{cryptoenginesv2.AlgRSASSAPKCS1V15SHA384, crypto.SHA384},
		{cryptoenginesv2.AlgRSASSAPKCS1V15SHA512, crypto.SHA512},
	}
	b := newTestBackend(t)
	h := generateKey(t, b, cryptoenginesv2.KeySpecRSA2048)
	signer := h.(cryptoenginesv2.Signer)
	pub := signer.Public().(*rsa.PublicKey)

	for _, tc := range cases {
		tc := tc
		t.Run(string(tc.alg), func(t *testing.T) {
			digest := hashMessage(tc.hash, []byte("rsa pkcs1 test"))
			sig, err := signer.SignContext(context.Background(), digest, tc.alg, tc.hash)
			require.NoError(t, err)
			assert.NoError(t, rsa.VerifyPKCS1v15(pub, tc.hash, digest, sig), "PKCS#1 v1.5 signature must verify")
		})
	}
}

func TestRSA_PSS_SignVerify(t *testing.T) {
	cases := []struct {
		alg  cryptoenginesv2.AlgorithmID
		hash crypto.Hash
	}{
		{cryptoenginesv2.AlgRSASSAPSSSHA256, crypto.SHA256},
		{cryptoenginesv2.AlgRSASSAPSSSHA384, crypto.SHA384},
		{cryptoenginesv2.AlgRSASSAPSSSHA512, crypto.SHA512},
	}
	b := newTestBackend(t)
	h := generateKey(t, b, cryptoenginesv2.KeySpecRSA2048)
	signer := h.(cryptoenginesv2.Signer)
	pub := signer.Public().(*rsa.PublicKey)

	for _, tc := range cases {
		tc := tc
		t.Run(string(tc.alg), func(t *testing.T) {
			digest := hashMessage(tc.hash, []byte("rsa pss test"))
			sig, err := signer.SignContext(context.Background(), digest, tc.alg, tc.hash)
			require.NoError(t, err)
			assert.NoError(t, rsa.VerifyPSS(pub, tc.hash, digest, sig, &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       tc.hash,
			}), "PSS signature must verify")
		})
	}
}

// ---------------------------------------------------------------------------
// RSA encryption / decryption (OAEP)
// ---------------------------------------------------------------------------

func TestRSA_OAEP_EncryptDecrypt(t *testing.T) {
	cases := []struct {
		alg  cryptoenginesv2.AlgorithmID
		hash crypto.Hash
	}{
		{cryptoenginesv2.AlgRSAESOAEPSHA256, crypto.SHA256},
		{cryptoenginesv2.AlgRSAESOAEPSHA1, crypto.SHA1},
	}
	b := newTestBackend(t)
	h := generateKey(t, b, cryptoenginesv2.KeySpecRSA2048)
	enc := h.(cryptoenginesv2.Encrypter)
	dec := h.(cryptoenginesv2.Decrypter)

	for _, tc := range cases {
		tc := tc
		t.Run(string(tc.alg), func(t *testing.T) {
			plaintext := []byte("secret payload for rsa oaep")
			ctx := context.Background()

			ct, err := enc.EncryptContext(ctx, plaintext, tc.alg, cryptoenginesv2.EncryptOpts{Hash: tc.hash})
			require.NoError(t, err)
			assert.NotEqual(t, plaintext, ct)

			got, err := dec.DecryptContext(ctx, ct, tc.alg, &rsa.OAEPOptions{Hash: tc.hash})
			require.NoError(t, err)
			assert.Equal(t, plaintext, got)
		})
	}
}

// ---------------------------------------------------------------------------
// RSA key wrap / unwrap
// ---------------------------------------------------------------------------

func TestRSA_WrapUnwrap(t *testing.T) {
	b := newTestBackend(t)
	h := generateKey(t, b, cryptoenginesv2.KeySpecRSA2048)

	wrapper, ok := h.(cryptoenginesv2.KeyWrapper)
	require.True(t, ok, "handle must implement KeyWrapper")

	// Simulate wrapping a 32-byte AES key.
	keyMaterial := make([]byte, 32)
	for i := range keyMaterial {
		keyMaterial[i] = byte(i)
	}

	ctx := context.Background()
	wrapped, err := wrapper.WrapKey(ctx, keyMaterial, cryptoenginesv2.AlgRSAESOAEPSHA256, cryptoenginesv2.WrapOpts{Hash: crypto.SHA256})
	require.NoError(t, err)
	assert.NotEmpty(t, wrapped)
	assert.False(t, bytes.Contains(wrapped, keyMaterial), "wrapped blob must not contain raw key material")

	unwrapped, err := wrapper.UnwrapKey(ctx, wrapped, cryptoenginesv2.AlgRSAESOAEPSHA256, cryptoenginesv2.WrapOpts{Hash: crypto.SHA256})
	require.NoError(t, err)
	assert.Equal(t, keyMaterial, unwrapped)
}

// ---------------------------------------------------------------------------
// HMAC
// ---------------------------------------------------------------------------

func TestHMAC_MACVerify(t *testing.T) {
	cases := []struct {
		spec cryptoenginesv2.KeySpec
		alg  cryptoenginesv2.AlgorithmID
	}{
		{cryptoenginesv2.KeySpecHMAC256, cryptoenginesv2.AlgHMACSHA256},
		{cryptoenginesv2.KeySpecHMAC384, cryptoenginesv2.AlgHMACSHA384},
		{cryptoenginesv2.KeySpecHMAC512, cryptoenginesv2.AlgHMACSHA512},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(string(tc.spec), func(t *testing.T) {
			b := newTestBackend(t)
			h := generateKey(t, b, tc.spec)

			macer, ok := h.(cryptoenginesv2.MACer)
			require.True(t, ok, "handle must implement MACer")

			message := []byte("authenticate this message")
			ctx := context.Background()

			mac, err := macer.MAC(ctx, message, tc.alg)
			require.NoError(t, err)
			assert.NotEmpty(t, mac)

			// Correct message → verify succeeds.
			err = macer.VerifyMAC(ctx, message, mac, tc.alg)
			assert.NoError(t, err)

			// Tampered message → verify fails.
			err = macer.VerifyMAC(ctx, append(message, '!'), mac, tc.alg)
			assert.Error(t, err, "tampered message must not verify")

			// Tampered MAC → verify fails.
			badMAC := append([]byte(nil), mac...)
			badMAC[0] ^= 0xFF
			err = macer.VerifyMAC(ctx, message, badMAC, tc.alg)
			assert.Error(t, err, "tampered MAC must not verify")
		})
	}
}

func TestHMAC_DifferentKeys_DifferentMACs(t *testing.T) {
	b := newTestBackend(t)
	h1 := generateKey(t, b, cryptoenginesv2.KeySpecHMAC256)
	h2 := generateKey(t, b, cryptoenginesv2.KeySpecHMAC256)

	macer1 := h1.(cryptoenginesv2.MACer)
	macer2 := h2.(cryptoenginesv2.MACer)

	message := []byte("same message")
	ctx := context.Background()

	mac1, err := macer1.MAC(ctx, message, cryptoenginesv2.AlgHMACSHA256)
	require.NoError(t, err)
	mac2, err := macer2.MAC(ctx, message, cryptoenginesv2.AlgHMACSHA256)
	require.NoError(t, err)

	assert.NotEqual(t, mac1, mac2, "different keys must produce different MACs")
}

// ---------------------------------------------------------------------------
// ML-KEM
// ---------------------------------------------------------------------------

func TestMLKEM_EncapsulateDecapsulate(t *testing.T) {
	for _, spec := range []cryptoenginesv2.KeySpec{
		cryptoenginesv2.KeySpecMLKEM768,
		cryptoenginesv2.KeySpecMLKEM1024,
	} {
		spec := spec
		t.Run(string(spec), func(t *testing.T) {
			b := newTestBackend(t)
			h := generateKey(t, b, spec)

			enc, ok := h.(cryptoenginesv2.Encapsulator)
			require.True(t, ok, "handle must implement Encapsulator")
			dec, ok := h.(cryptoenginesv2.Decapsulator)
			require.True(t, ok, "handle must implement Decapsulator")

			ctx := context.Background()

			ss1, ct, err := enc.EncapsulateContext(ctx)
			require.NoError(t, err)
			assert.NotEmpty(t, ss1)
			assert.NotEmpty(t, ct)

			ss2, err := dec.DecapsulateContext(ctx, ct)
			require.NoError(t, err)

			assert.Equal(t, ss1, ss2, "encapsulated and decapsulated shared secrets must match")
		})
	}
}

func TestMLKEM_TamperedCiphertext(t *testing.T) {
	b := newTestBackend(t)
	h := generateKey(t, b, cryptoenginesv2.KeySpecMLKEM768)
	enc := h.(cryptoenginesv2.Encapsulator)
	dec := h.(cryptoenginesv2.Decapsulator)

	ctx := context.Background()
	_, ct, err := enc.EncapsulateContext(ctx)
	require.NoError(t, err)

	tampered := append([]byte(nil), ct...)
	tampered[0] ^= 0xFF

	ss, err := dec.DecapsulateContext(ctx, tampered)
	// ML-KEM decapsulation is designed to be implicit-rejection: it does not
	// return an error but instead returns a pseudorandom value different from
	// the genuine shared secret. Either outcome (error or different SS) is
	// acceptable here.
	if err == nil {
		_, origCT, _ := enc.EncapsulateContext(ctx)
		origSS, _ := dec.DecapsulateContext(ctx, origCT)
		assert.NotEqual(t, origSS, ss, "tampered ciphertext must not yield same shared secret")
	}
}

// ---------------------------------------------------------------------------
// Handle lifecycle
// ---------------------------------------------------------------------------

func TestHandle_ClosePreventsUse(t *testing.T) {
	b := newTestBackend(t)
	h := generateKey(t, b, cryptoenginesv2.KeySpecSymmetricDefault)
	cipher := h.(cryptoenginesv2.SymmetricCipher)

	require.NoError(t, h.Close())

	_, err := cipher.Encrypt(context.Background(), []byte("hi"), cryptoenginesv2.AlgSymmetricDefault, cryptoenginesv2.SymmetricOpts{})
	assert.Error(t, err, "closed handle must return an error")
}

// ---------------------------------------------------------------------------
// Import
// ---------------------------------------------------------------------------

func TestImport_RoundtripAES(t *testing.T) {
	b := newTestBackend(t)

	rawKey := make([]byte, 32) // 256-bit AES key
	for i := range rawKey {
		rawKey[i] = byte(i + 1)
	}

	keySeq++
	h, err := b.Import(context.Background(), cryptoenginesv2.ImportKeySpec{
		KeyID:       cryptoenginesv2.KeyID(fmt.Sprintf("import-%d", keySeq)),
		KeySpec:     cryptoenginesv2.KeySpecSymmetricDefault,
		KeyMaterial: rawKey,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = h.Close() })

	cipher := h.(cryptoenginesv2.SymmetricCipher)
	plaintext := []byte("imported key encryption test")
	ctx := context.Background()

	ct, err := cipher.Encrypt(ctx, plaintext, cryptoenginesv2.AlgSymmetricDefault, cryptoenginesv2.SymmetricOpts{})
	require.NoError(t, err)

	got, err := cipher.Decrypt(ctx, ct, cryptoenginesv2.SymmetricOpts{})
	require.NoError(t, err)
	assert.Equal(t, plaintext, got)
}

// ---------------------------------------------------------------------------
// Internal helper
// ---------------------------------------------------------------------------

func hashMessage(h crypto.Hash, msg []byte) []byte {
	switch h {
	case crypto.SHA256:
		d := sha256.Sum256(msg)
		return d[:]
	case crypto.SHA384:
		d := sha512.Sum384(msg)
		return d[:]
	case crypto.SHA512:
		d := sha512.Sum512(msg)
		return d[:]
	case crypto.SHA1:
		d := sha1.Sum(msg) //nolint:gosec -- SHA-1 used only to exercise OAEP-SHA1 test vector
		return d[:]
	default:
		panic(fmt.Sprintf("hashMessage: unsupported hash %v", h))
	}
}
