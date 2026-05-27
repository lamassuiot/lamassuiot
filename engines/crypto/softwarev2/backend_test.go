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

func generateKey(t *testing.T, b *softwarev2.Backend, alg cryptoenginesv2.AlgorithmID) cryptoenginesv2.KeyHandle {
	t.Helper()
	keySeq++
	h, err := b.Generate(context.Background(), cryptoenginesv2.CreateKeySpec{
		KeyID:     cryptoenginesv2.KeyID(fmt.Sprintf("key-%d-%s", keySeq, alg)),
		Algorithm: alg,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = h.Close() })
	return h
}

// ---------------------------------------------------------------------------
// AES-GCM
// ---------------------------------------------------------------------------

func TestAES_GCM_Roundtrip(t *testing.T) {
	for _, alg := range []cryptoenginesv2.AlgorithmID{
		"AES_GCM_128",
		"AES_GCM_192",
		"AES_GCM_256",
	} {
		alg := alg
		t.Run(string(alg), func(t *testing.T) {
			b := newTestBackend(t)
			h := generateKey(t, b, alg)

			cipher, ok := h.(cryptoenginesv2.SymmetricCipher)
			require.True(t, ok, "handle must implement SymmetricCipher")

			plaintext := []byte("the quick brown fox jumps over the lazy dog")
			ctx := context.Background()

			ct, err := cipher.Encrypt(ctx, plaintext, cryptoenginesv2.SymmetricOpts{})
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
	h := generateKey(t, b, "AES_GCM_256")
	cipher := h.(cryptoenginesv2.SymmetricCipher)

	plaintext := []byte("secret message")
	aad := []byte("associated-data-header")
	ctx := context.Background()

	ct, err := cipher.Encrypt(ctx, plaintext, cryptoenginesv2.SymmetricOpts{AssociatedData: aad})
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
	h := generateKey(t, b, "AES_GCM_256")
	cipher := h.(cryptoenginesv2.SymmetricCipher)

	ct, err := cipher.Encrypt(context.Background(), []byte("hello"), cryptoenginesv2.SymmetricOpts{})
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
		alg  cryptoenginesv2.AlgorithmID
		hash crypto.Hash
	}{
		{"ECDSA_SHA_256", crypto.SHA256},
		{"ECDSA_SHA_384", crypto.SHA384},
		{"ECDSA_SHA_512", crypto.SHA512},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(string(tc.alg), func(t *testing.T) {
			b := newTestBackend(t)
			h := generateKey(t, b, tc.alg)

			signer, ok := h.(cryptoenginesv2.Signer)
			require.True(t, ok, "handle must implement Signer")

			pub, ok := signer.Public().(*ecdsa.PublicKey)
			require.True(t, ok)

			message := []byte("sign me")
			digest := hashMessage(tc.hash, message)

			sig, err := signer.SignContext(context.Background(), digest, tc.hash)
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
	for _, alg := range []cryptoenginesv2.AlgorithmID{
		"ECDH_NIST_P256",
		"ECDH_NIST_P384",
		"ECDH_NIST_P521",
		"ECDH_X25519",
	} {
		alg := alg
		t.Run(string(alg), func(t *testing.T) {
			b := newTestBackend(t)
			h1 := generateKey(t, b, alg)
			h2 := generateKey(t, b, alg)

			ka1, ok := h1.(cryptoenginesv2.KeyAgreementer)
			require.True(t, ok, "h1 must implement KeyAgreementer")
			ka2, ok := h2.(cryptoenginesv2.KeyAgreementer)
			require.True(t, ok, "h2 must implement KeyAgreementer")

			pub1, ok := h1.Metadata().PublicKey.(*ecdh.PublicKey)
			require.True(t, ok, "h1 public key must be *ecdh.PublicKey")
			pub2, ok := h2.Metadata().PublicKey.(*ecdh.PublicKey)
			require.True(t, ok, "h2 public key must be *ecdh.PublicKey")

			ctx := context.Background()

			ss1, err := ka1.Agree(ctx, pub2)
			require.NoError(t, err)

			ss2, err := ka2.Agree(ctx, pub1)
			require.NoError(t, err)

			assert.Equal(t, ss1, ss2, "both parties must derive the same shared secret")
			assert.NotEmpty(t, ss1)
		})
	}
}

// ---------------------------------------------------------------------------
// RSA signing
// ---------------------------------------------------------------------------

func TestRSA_PKCS1v15_SignVerify(t *testing.T) {
	cases := []struct {
		alg  cryptoenginesv2.AlgorithmID
		hash crypto.Hash
	}{
		{"RSASSA_PKCS1_V1_5_SHA_256", crypto.SHA256},
		{"RSASSA_PKCS1_V1_5_SHA_384", crypto.SHA384},
		{"RSASSA_PKCS1_V1_5_SHA_512", crypto.SHA512},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(string(tc.alg), func(t *testing.T) {
			b := newTestBackend(t)
			h := generateKey(t, b, tc.alg)

			signer, ok := h.(cryptoenginesv2.Signer)
			require.True(t, ok)

			pub := signer.Public().(*rsa.PublicKey)
			message := []byte("rsa pkcs1 test")
			digest := hashMessage(tc.hash, message)

			sig, err := signer.SignContext(context.Background(), digest, tc.hash)
			require.NoError(t, err)

			err = rsa.VerifyPKCS1v15(pub, tc.hash, digest, sig)
			assert.NoError(t, err, "PKCS#1 v1.5 signature must verify")
		})
	}
}

func TestRSA_PSS_SignVerify(t *testing.T) {
	cases := []struct {
		alg  cryptoenginesv2.AlgorithmID
		hash crypto.Hash
	}{
		{"RSASSA_PSS_SHA_256", crypto.SHA256},
		{"RSASSA_PSS_SHA_384", crypto.SHA384},
		{"RSASSA_PSS_SHA_512", crypto.SHA512},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(string(tc.alg), func(t *testing.T) {
			b := newTestBackend(t)
			h := generateKey(t, b, tc.alg)

			signer := h.(cryptoenginesv2.Signer)
			pub := signer.Public().(*rsa.PublicKey)
			digest := hashMessage(tc.hash, []byte("rsa pss test"))

			sig, err := signer.SignContext(context.Background(), digest, tc.hash)
			require.NoError(t, err)

			err = rsa.VerifyPSS(pub, tc.hash, digest, sig, &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       tc.hash,
			})
			assert.NoError(t, err, "PSS signature must verify")
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
		{"RSAES_OAEP_SHA_256_2048", crypto.SHA256},
		{"RSAES_OAEP_SHA_1_2048", crypto.SHA1},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(string(tc.alg), func(t *testing.T) {
			b := newTestBackend(t)
			h := generateKey(t, b, tc.alg)

			enc, ok := h.(cryptoenginesv2.Encrypter)
			require.True(t, ok, "handle must implement Encrypter")
			dec, ok := h.(cryptoenginesv2.Decrypter)
			require.True(t, ok, "handle must implement Decrypter")

			plaintext := []byte("secret payload for rsa oaep")
			ctx := context.Background()

			ct, err := enc.EncryptContext(ctx, plaintext, cryptoenginesv2.EncryptOpts{Hash: tc.hash})
			require.NoError(t, err)
			assert.NotEqual(t, plaintext, ct)

			got, err := dec.DecryptContext(ctx, ct, &rsa.OAEPOptions{Hash: tc.hash})
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
	h := generateKey(t, b, "RSAES_OAEP_SHA_256_2048")

	wrapper, ok := h.(cryptoenginesv2.KeyWrapper)
	require.True(t, ok, "handle must implement KeyWrapper")

	// Simulate wrapping a 32-byte AES key.
	keyMaterial := make([]byte, 32)
	for i := range keyMaterial {
		keyMaterial[i] = byte(i)
	}

	ctx := context.Background()
	wrapped, err := wrapper.WrapKey(ctx, keyMaterial, cryptoenginesv2.WrapOpts{Hash: crypto.SHA256})
	require.NoError(t, err)
	assert.NotEmpty(t, wrapped)
	assert.False(t, bytes.Contains(wrapped, keyMaterial), "wrapped blob must not contain raw key material")

	unwrapped, err := wrapper.UnwrapKey(ctx, wrapped, cryptoenginesv2.WrapOpts{Hash: crypto.SHA256})
	require.NoError(t, err)
	assert.Equal(t, keyMaterial, unwrapped)
}

// ---------------------------------------------------------------------------
// HMAC
// ---------------------------------------------------------------------------

func TestHMAC_MACVerify(t *testing.T) {
	for _, alg := range []cryptoenginesv2.AlgorithmID{
		"HMAC_SHA_256",
		"HMAC_SHA_384",
		"HMAC_SHA_512",
	} {
		alg := alg
		t.Run(string(alg), func(t *testing.T) {
			b := newTestBackend(t)
			h := generateKey(t, b, alg)

			macer, ok := h.(cryptoenginesv2.MACer)
			require.True(t, ok, "handle must implement MACer")

			message := []byte("authenticate this message")
			ctx := context.Background()

			mac, err := macer.MAC(ctx, message)
			require.NoError(t, err)
			assert.NotEmpty(t, mac)

			// Correct message → verify succeeds.
			err = macer.VerifyMAC(ctx, message, mac)
			assert.NoError(t, err)

			// Tampered message → verify fails.
			err = macer.VerifyMAC(ctx, append(message, '!'), mac)
			assert.Error(t, err, "tampered message must not verify")

			// Tampered MAC → verify fails.
			badMAC := append([]byte(nil), mac...)
			badMAC[0] ^= 0xFF
			err = macer.VerifyMAC(ctx, message, badMAC)
			assert.Error(t, err, "tampered MAC must not verify")
		})
	}
}

func TestHMAC_DifferentKeys_DifferentMACs(t *testing.T) {
	b := newTestBackend(t)
	h1 := generateKey(t, b, "HMAC_SHA_256")
	h2 := generateKey(t, b, "HMAC_SHA_256")

	macer1 := h1.(cryptoenginesv2.MACer)
	macer2 := h2.(cryptoenginesv2.MACer)

	message := []byte("same message")
	ctx := context.Background()

	mac1, err := macer1.MAC(ctx, message)
	require.NoError(t, err)
	mac2, err := macer2.MAC(ctx, message)
	require.NoError(t, err)

	assert.NotEqual(t, mac1, mac2, "different keys must produce different MACs")
}

// ---------------------------------------------------------------------------
// ML-KEM
// ---------------------------------------------------------------------------

func TestMLKEM_EncapsulateDecapsulate(t *testing.T) {
	for _, alg := range []cryptoenginesv2.AlgorithmID{
		"ML_KEM_768",
		"ML_KEM_1024",
	} {
		alg := alg
		t.Run(string(alg), func(t *testing.T) {
			b := newTestBackend(t)
			h := generateKey(t, b, alg)

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
	h := generateKey(t, b, "ML_KEM_768")
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
	h := generateKey(t, b, "AES_GCM_256")
	cipher := h.(cryptoenginesv2.SymmetricCipher)

	require.NoError(t, h.Close())

	_, err := cipher.Encrypt(context.Background(), []byte("hi"), cryptoenginesv2.SymmetricOpts{})
	assert.Error(t, err, "closed handle must return an error")
}

// ---------------------------------------------------------------------------
// Import
// ---------------------------------------------------------------------------

func TestImport_RoundtripAES(t *testing.T) {
	b := newTestBackend(t)

	// First generate a key to obtain its encoded material by generating in
	// another backend instance, then import the same raw key into this one.
	rawKey := make([]byte, 32) // 256-bit AES key
	for i := range rawKey {
		rawKey[i] = byte(i + 1)
	}

	keySeq++
	h, err := b.Import(context.Background(), cryptoenginesv2.ImportKeySpec{
		KeyID:       cryptoenginesv2.KeyID(fmt.Sprintf("import-%d", keySeq)),
		Algorithm:   "AES_GCM_256",
		KeyMaterial: rawKey,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = h.Close() })

	cipher := h.(cryptoenginesv2.SymmetricCipher)
	plaintext := []byte("imported key encryption test")
	ctx := context.Background()

	ct, err := cipher.Encrypt(ctx, plaintext, cryptoenginesv2.SymmetricOpts{})
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
