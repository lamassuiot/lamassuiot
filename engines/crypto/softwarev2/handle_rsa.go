package softwarev2

import (
	"context"
	"crypto"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"

	cryptoenginesv2 "github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines_v2"
)

// rsaHandle implements cryptoenginesv2.Signer, cryptoenginesv2.Encrypter,
// cryptoenginesv2.Decrypter, and cryptoenginesv2.KeyWrapper for RSA keys.
// A single RSA key (KeySpec RSA_2048/3072/4096) serves every RSASSA_* signing
// algorithm and every RSAES_* encryption algorithm; the per-operation algorithm
// is chosen at call time. Material is loaded fresh on every operation and zeroized.
type rsaHandle struct {
	*handleBase
}

// --- crypto.Signer / cryptoenginesv2.Signer ---

func (h *rsaHandle) Public() crypto.PublicKey { return h.meta.PublicKey }

// Sign implements crypto.Signer. It infers the algorithm from opts: an
// *rsa.PSSOptions selects PSS, otherwise PKCS#1 v1.5; the hash comes from opts.
func (h *rsaHandle) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	_ = rand // backend uses its own randomness source
	scheme := "pkcs1v15"
	var hash crypto.Hash
	if pss, ok := opts.(*rsa.PSSOptions); ok {
		scheme = "pss"
		hash = pss.Hash
	} else if opts != nil {
		hash = opts.HashFunc()
	}
	return h.signInternal(context.Background(), digest, scheme, hash)
}

func (h *rsaHandle) SignContext(ctx context.Context, digest []byte, alg cryptoenginesv2.AlgorithmID, opts crypto.SignerOpts) ([]byte, error) {
	scheme, hash, ok := rsaSignParams(alg)
	if !ok {
		return nil, fmt.Errorf("soft: %s is not an RSA signing algorithm", alg)
	}
	return h.signInternal(ctx, digest, scheme, hash)
}

func (h *rsaHandle) signInternal(ctx context.Context, digest []byte, scheme string, hash crypto.Hash) ([]byte, error) {
	if hash == 0 {
		return nil, errors.New("soft: RSA sign requires a hash")
	}

	blob, err := h.loadMaterial(ctx)
	if err != nil {
		return nil, err
	}
	defer zero(blob)

	priv, err := decodePrivate(h.meta.KeySpec, blob)
	if err != nil {
		return nil, err
	}
	sk, ok := priv.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("soft: %s did not decode to RSA private key", h.meta.KeySpec)
	}

	switch scheme {
	case "pss":
		return rsa.SignPSS(randomReader, sk, hash, digest, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       hash,
		})
	case "pkcs1v15":
		return rsa.SignPKCS1v15(randomReader, sk, hash, digest)
	}
	return nil, fmt.Errorf("soft: unknown RSA signing scheme %q", scheme)
}

// --- cryptoenginesv2.Encrypter ---

func (h *rsaHandle) EncryptContext(ctx context.Context, plaintext []byte, alg cryptoenginesv2.AlgorithmID, opts cryptoenginesv2.EncryptOpts) ([]byte, error) {
	_ = ctx // public-key encryption does not need private material loading today
	hash, ok := rsaOAEPHash(alg)
	if !ok {
		return nil, fmt.Errorf("soft: %s is not an RSA encryption algorithm", alg)
	}
	if opts.Hash != 0 {
		hash = opts.Hash
	}

	pub, ok := h.meta.PublicKey.(*rsa.PublicKey)
	if !ok || pub == nil {
		return nil, errors.New("soft: missing RSA public key for encrypt")
	}
	return rsa.EncryptOAEP(hash.New(), randomReader, pub, plaintext, opts.AssociatedData)
}

// --- crypto.Decrypter / cryptoenginesv2.Decrypter ---

func (h *rsaHandle) Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	_ = rand
	// stdlib path: *rsa.OAEPOptions selects OAEP, otherwise PKCS#1 v1.5.
	if oaep, ok := opts.(*rsa.OAEPOptions); ok {
		hash := oaep.Hash
		if hash == 0 {
			hash = crypto.SHA256
		}
		return h.decryptInternal(context.Background(), msg, true, hash, oaep.Label)
	}
	return h.decryptInternal(context.Background(), msg, false, 0, nil)
}

func (h *rsaHandle) DecryptContext(ctx context.Context, ciphertext []byte, alg cryptoenginesv2.AlgorithmID, opts crypto.DecrypterOpts) ([]byte, error) {
	if hash, ok := rsaOAEPHash(alg); ok {
		var label []byte
		if oaep, ok := opts.(*rsa.OAEPOptions); ok {
			label = oaep.Label
			if oaep.Hash != 0 {
				hash = oaep.Hash
			}
		}
		return h.decryptInternal(ctx, ciphertext, true, hash, label)
	}
	if isRSALegacyPKCS1Enc(alg) {
		return h.decryptInternal(ctx, ciphertext, false, 0, nil)
	}
	return nil, fmt.Errorf("soft: %s is not an RSA decryption algorithm", alg)
}

func (h *rsaHandle) decryptInternal(ctx context.Context, ct []byte, oaep bool, hash crypto.Hash, label []byte) ([]byte, error) {
	blob, err := h.loadMaterial(ctx)
	if err != nil {
		return nil, err
	}
	defer zero(blob)

	priv, err := decodePrivate(h.meta.KeySpec, blob)
	if err != nil {
		return nil, err
	}
	sk, ok := priv.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("soft: %s did not decode to RSA private key", h.meta.KeySpec)
	}

	if oaep {
		return rsa.DecryptOAEP(hash.New(), randomReader, sk, ct, label)
	}
	// RSA PKCS#1 v1.5 — legacy decrypt only. Constant-time path to mitigate
	// Bleichenbacher.
	return rsa.DecryptPKCS1v15(randomReader, sk, ct)
}

// --- cryptoenginesv2.KeyWrapper ---

// WrapKey wraps arbitrary key material using RSA-OAEP. Only valid for
// RSAES_OAEP_* algorithms (RSAES_PKCS1_V1_5 is decrypt-only and never wraps).
func (h *rsaHandle) WrapKey(ctx context.Context, keyMaterial []byte, alg cryptoenginesv2.AlgorithmID, opts cryptoenginesv2.WrapOpts) ([]byte, error) {
	hash, ok := rsaOAEPHash(alg)
	if !ok {
		return nil, fmt.Errorf("soft: %s cannot wrap keys", alg)
	}
	if opts.Hash != 0 {
		hash = opts.Hash
	}
	pub, ok := h.meta.PublicKey.(*rsa.PublicKey)
	if !ok || pub == nil {
		return nil, errors.New("soft: missing RSA public key for wrap")
	}
	return rsa.EncryptOAEP(hash.New(), randomReader, pub, keyMaterial, opts.AssociatedData)
}

// UnwrapKey reverses WrapKey.
func (h *rsaHandle) UnwrapKey(ctx context.Context, wrapped []byte, alg cryptoenginesv2.AlgorithmID, opts cryptoenginesv2.WrapOpts) ([]byte, error) {
	hash, ok := rsaOAEPHash(alg)
	if !ok {
		return nil, fmt.Errorf("soft: %s cannot unwrap keys", alg)
	}
	if opts.Hash != 0 {
		hash = opts.Hash
	}
	return h.decryptInternal(ctx, wrapped, true, hash, opts.AssociatedData)
}
