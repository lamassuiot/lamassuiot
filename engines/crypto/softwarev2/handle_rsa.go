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
// cryptoenginesv2.Decrypter, and cryptoenginesv2.KeyWrapper for
// RSA keys. Material is loaded fresh on every operation and zeroized.
type rsaHandle struct {
	handleBase
}

// --- crypto.Signer / cryptoenginesv2.Signer ---

func (h *rsaHandle) Public() crypto.PublicKey { return h.meta.PublicKey }

// Sign implements crypto.Signer. It does not accept a context; the
// background context is used. For context-aware callers, use SignContext.
func (h *rsaHandle) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	_ = rand // backend uses its own randomness source
	return h.signInternal(context.Background(), digest, opts)
}

func (h *rsaHandle) SignContext(ctx context.Context, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return h.signInternal(ctx, digest, opts)
}

func (h *rsaHandle) signInternal(ctx context.Context, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	blob, err := h.loadMaterial(ctx)
	if err != nil {
		return nil, err
	}
	defer zero(blob)

	priv, err := decodePrivate(h.meta.Algorithm, blob)
	if err != nil {
		return nil, err
	}
	sk, ok := priv.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("soft: %s did not decode to RSA private key", h.meta.Algorithm)
	}

	// Determine PSS vs PKCS#1 v1.5 from algorithm ID. If opts is *rsa.PSSOptions
	// the caller forced PSS; otherwise fall back to the algorithm's default.
	if pssOpts, isPSS := opts.(*rsa.PSSOptions); isPSS {
		return rsa.SignPSS(randomReader, sk, pssOpts.Hash, digest, pssOpts)
	}

	var hash crypto.Hash
	if opts != nil {
		hash = opts.HashFunc()
	}
	if hash == 0 {
		hash = rsaHashFor(h.meta.Algorithm)
	}

	switch h.meta.Algorithm {
	case "RSASSA_PSS_SHA_256", "RSASSA_PSS_SHA_384", "RSASSA_PSS_SHA_512":
		return rsa.SignPSS(randomReader, sk, hash, digest, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       hash,
		})
	case "RSASSA_PKCS1_V1_5_SHA_256", "RSASSA_PKCS1_V1_5_SHA_384", "RSASSA_PKCS1_V1_5_SHA_512":
		return rsa.SignPKCS1v15(randomReader, sk, hash, digest)
	}
	return nil, fmt.Errorf("soft: algorithm %s is not a signing algorithm", h.meta.Algorithm)
}

// --- cryptoenginesv2.Encrypter ---

func (h *rsaHandle) EncryptContext(ctx context.Context, plaintext []byte, opts cryptoenginesv2.EncryptOpts) ([]byte, error) {
	_ = ctx // public-key encryption does not need private material loading today
	if !hasPrefix(string(h.meta.Algorithm), "RSAES_OAEP_") {
		return nil, fmt.Errorf("soft: %s does not support encrypt", h.meta.Algorithm)
	}

	pub, ok := h.meta.PublicKey.(*rsa.PublicKey)
	if !ok || pub == nil {
		return nil, errors.New("soft: missing RSA public key for encrypt")
	}

	hash := pickHash(opts.Hash, rsaHashFor(h.meta.Algorithm))
	return rsa.EncryptOAEP(hash.New(), randomReader, pub, plaintext, opts.AssociatedData)
}

// --- crypto.Decrypter / cryptoenginesv2.Decrypter ---

func (h *rsaHandle) Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	_ = rand
	return h.decryptInternal(context.Background(), msg, opts)
}

func (h *rsaHandle) DecryptContext(ctx context.Context, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	return h.decryptInternal(ctx, ciphertext, opts)
}

func (h *rsaHandle) decryptInternal(ctx context.Context, ct []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	if !h.canDecrypt() {
		return nil, fmt.Errorf("soft: algorithm %s is not a decryption algorithm", h.meta.Algorithm)
	}

	blob, err := h.loadMaterial(ctx)
	if err != nil {
		return nil, err
	}
	defer zero(blob)

	priv, err := decodePrivate(h.meta.Algorithm, blob)
	if err != nil {
		return nil, err
	}
	sk := priv.(*rsa.PrivateKey)

	// RSA-OAEP path
	if hasPrefix(string(h.meta.Algorithm), "RSAES_OAEP_") {
		hash := rsaHashFor(h.meta.Algorithm)
		var label []byte
		if oaep, ok := opts.(*rsa.OAEPOptions); ok {
			label = oaep.Label
			if oaep.Hash != 0 {
				hash = oaep.Hash
			}
		}
		return rsa.DecryptOAEP(hash.New(), randomReader, sk, ct, label)
	}

	// RSA PKCS#1 v1.5 — legacy decrypt only
	if hasPrefix(string(h.meta.Algorithm), "RSAES_PKCS1_V1_5_") {
		// Constant-time path to mitigate Bleichenbacher; rsa.DecryptPKCS1v15
		// returns an error or the plaintext.
		return rsa.DecryptPKCS1v15(randomReader, sk, ct)
	}

	return nil, fmt.Errorf("soft: %s does not support decrypt", h.meta.Algorithm)
}

func (h *rsaHandle) canDecrypt() bool {
	return hasPrefix(string(h.meta.Algorithm), "RSAES_OAEP_") ||
		hasPrefix(string(h.meta.Algorithm), "RSAES_PKCS1_V1_5_")
}

// --- cryptoenginesv2.KeyWrapper ---

// WrapKey wraps arbitrary key material using RSA-OAEP. Only valid for
// RSAES_OAEP_* algorithms (RSAES_PKCS1_V1_5_* is decrypt-only and never wraps).
func (h *rsaHandle) WrapKey(ctx context.Context, keyMaterial []byte, opts cryptoenginesv2.WrapOpts) ([]byte, error) {
	if !hasPrefix(string(h.meta.Algorithm), "RSAES_OAEP_") {
		return nil, fmt.Errorf("soft: %s cannot wrap keys", h.meta.Algorithm)
	}
	pub, ok := h.meta.PublicKey.(*rsa.PublicKey)
	if !ok || pub == nil {
		return nil, errors.New("soft: missing RSA public key for wrap")
	}
	hash := rsaHashFor(h.meta.Algorithm)
	if opts.Hash != 0 {
		hash = opts.Hash
	}
	return rsa.EncryptOAEP(hash.New(), randomReader, pub, keyMaterial, opts.AssociatedData)
}

// UnwrapKey reverses WrapKey.
func (h *rsaHandle) UnwrapKey(ctx context.Context, wrapped []byte, opts cryptoenginesv2.WrapOpts) ([]byte, error) {
	return h.decryptInternal(ctx, wrapped, &rsa.OAEPOptions{
		Hash:  pickHash(opts.Hash, rsaHashFor(h.meta.Algorithm)),
		Label: opts.AssociatedData,
	})
}

func pickHash(want, fallback crypto.Hash) crypto.Hash {
	if want != 0 {
		return want
	}
	return fallback
}
