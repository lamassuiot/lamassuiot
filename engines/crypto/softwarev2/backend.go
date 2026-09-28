package softwarev2

// Package softwarev2 is an in-process Backend implementation that stores key
// material as plain canonical bytes in a pluggable BlobStore (filesystem
// by default).
//
// SECURITY: this phase intentionally does NOT encrypt blobs at rest.
// Private key material is written verbatim to the BlobStore as PKCS#8
// (asymmetric) or raw bytes (symmetric / ML-KEM seed). Protection relies
// entirely on filesystem permissions and the surrounding environment.
//
// DO NOT use this backend for production. For production, use
// backend/pkcs11 (HSM), backend/awskms (upstream), or extend this package
// with a KEK layer in a follow-up phase.
//
// It implements the full cryptoenginesv2.Backend interface and produces KeyHandles
// satisfying the capability interfaces from package cryptoenginesv2 (Signer,
// cryptoenginesv2.Decrypter, cryptoenginesv2.Encapsulator, cryptoenginesv2.Decapsulator, cryptoenginesv2.KeyWrapper,
// cryptoenginesv2.SymmetricCipher, cryptoenginesv2.MACer, cryptoenginesv2.KeyAgreementer).

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"

	cryptoenginesv2 "github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines_v2"
	"gocloud.dev/blob"
)

// Backend implements cryptoenginesv2.Backend. Construct with New.
type Backend struct {
	name  string
	blobs *blob.Bucket
}

// Options configures a Backend.
type Options struct {
	// Name is the backend identifier persisted in BackendRef.Backend.
	// Defaults to "soft".
	Name string

	// Blobs is the storage for key blobs. Required. Blobs are written in
	// plain canonical form — see the package documentation.
	Blobs *blob.Bucket
}

// New builds a Backend from options.
func New(opts Options) (*Backend, error) {
	if opts.Blobs == nil {
		return nil, errors.New("soft: Options.Blobs is required")
	}
	name := opts.Name
	if name == "" {
		name = "soft"
	}
	return &Backend{name: name, blobs: opts.Blobs}, nil
}

func (b *Backend) Name() string { return b.name }

func (b *Backend) Capabilities() cryptoenginesv2.BackendCapabilities {
	return cryptoenginesv2.BackendCapabilities{
		KeySpecs: []cryptoenginesv2.KeySpec{
			// RSA — one keypair serves signing, OAEP encryption and wrapping.
			cryptoenginesv2.KeySpecRSA2048, cryptoenginesv2.KeySpecRSA3072, cryptoenginesv2.KeySpecRSA4096,
			// EC — one keypair serves ECDSA signing and ECDH agreement.
			cryptoenginesv2.KeySpecECCNISTP256, cryptoenginesv2.KeySpecECCNISTP384, cryptoenginesv2.KeySpecECCNISTP521,
			// X25519 (agreement only)
			cryptoenginesv2.KeySpecX25519,
			// ML-KEM (stdlib ships 768 and 1024)
			cryptoenginesv2.KeySpecMLKEM768, cryptoenginesv2.KeySpecMLKEM1024,
			// Symmetric AEAD
			cryptoenginesv2.KeySpecSymmetricDefault, cryptoenginesv2.KeySpecAES128, cryptoenginesv2.KeySpecAES192,
			// HMAC
			cryptoenginesv2.KeySpecHMAC256, cryptoenginesv2.KeySpecHMAC384, cryptoenginesv2.KeySpecHMAC512,
		},
		Operations: []cryptoenginesv2.Operation{
			cryptoenginesv2.OpSign, cryptoenginesv2.OpVerify,
			cryptoenginesv2.OpEncrypt, cryptoenginesv2.OpDecrypt,
			cryptoenginesv2.OpWrapKey, cryptoenginesv2.OpUnwrapKey,
			cryptoenginesv2.OpEncapsulate, cryptoenginesv2.OpDecapsulate,
			cryptoenginesv2.OpAgreeKey, cryptoenginesv2.OpDeriveKey,
			cryptoenginesv2.OpMAC, cryptoenginesv2.OpVerifyMAC,
		},
		Extractable: true,
	}
}

func (b *Backend) Generate(ctx context.Context, spec cryptoenginesv2.CreateKeySpec) (cryptoenginesv2.KeyHandle, error) {
	if spec.KeyID == "" {
		return nil, errors.New("soft: spec.KeyID must be assigned by the Service before calling Generate")
	}

	priv, pub, err := generateMaterial(spec.KeySpec)
	if err != nil {
		return nil, fmt.Errorf("soft: generate %s: %w", spec.KeySpec, err)
	}

	blob, err := encodePrivate(spec.KeySpec, priv)
	if err != nil {
		return nil, fmt.Errorf("soft: encode private: %w", err)
	}
	defer zero(blob)

	uri := blobURI(spec.KeyID)
	if err := b.blobs.WriteAll(ctx, uri, blob, nil); err != nil {
		return nil, fmt.Errorf("soft: persist blob: %w", err)
	}

	meta := cryptoenginesv2.KeyMetadata{
		KeyID:      spec.KeyID,
		KeySpec:    spec.KeySpec,
		Operations: spec.Operations,
		State:      cryptoenginesv2.StateEnabled,
		PublicKey:  pub,
		NotBefore:  spec.NotBefore,
		NotAfter:   spec.NotAfter,
		Origin:     cryptoenginesv2.OriginGenerated,
		Tags:       spec.Tags,
		PolicyID:   spec.PolicyID,
	}
	return b.newHandle(meta, uri)
}

func (b *Backend) Import(ctx context.Context, spec cryptoenginesv2.ImportKeySpec) (cryptoenginesv2.KeyHandle, error) {
	if spec.KeyID == "" {
		return nil, errors.New("soft: spec.KeyID must be assigned by the Service before calling Import")
	}
	if len(spec.KeyMaterial) == 0 {
		return nil, errors.New("soft: spec.KeyMaterial is empty")
	}

	pub, err := publicFromPrivate(spec.KeySpec, spec.KeyMaterial)
	if err != nil {
		return nil, fmt.Errorf("soft: parse imported %s: %w", spec.KeySpec, err)
	}

	// Persist the imported bytes verbatim. The caller chose plain-bytes
	// BYOK; we honor that.
	uri := blobURI(spec.KeyID)
	if err := b.blobs.WriteAll(ctx, uri, spec.KeyMaterial, nil); err != nil {
		return nil, fmt.Errorf("soft: persist imported blob: %w", err)
	}

	meta := cryptoenginesv2.KeyMetadata{
		KeyID:      spec.KeyID,
		KeySpec:    spec.KeySpec,
		Operations: spec.Operations,
		State:      cryptoenginesv2.StateEnabled,
		PublicKey:  pub,
		NotBefore:  spec.NotBefore,
		NotAfter:   spec.NotAfter,
		Origin:     cryptoenginesv2.OriginImported,
		Tags:       spec.Tags,
		PolicyID:   spec.PolicyID,
	}
	return b.newHandle(meta, uri)
}

func (b *Backend) Load(ctx context.Context, rec cryptoenginesv2.KeyRecord) (cryptoenginesv2.KeyHandle, error) {
	if rec.BackendRef.Backend != b.name {
		return nil, fmt.Errorf("soft: ref.Backend=%q does not match this backend %q", rec.BackendRef.Backend, b.name)
	}
	if _, err := b.blobs.Attributes(ctx, rec.BackendRef.URI); err != nil {
		return nil, fmt.Errorf("soft: blob missing for %s: %w", rec.Metadata.KeyID, err)
	}
	return b.newHandle(rec.Metadata, rec.BackendRef.URI)
}

func (b *Backend) Destroy(ctx context.Context, ref cryptoenginesv2.BackendRef) error {
	if ref.Backend != b.name {
		return fmt.Errorf("soft: ref.Backend=%q does not match this backend %q", ref.Backend, b.name)
	}
	return b.blobs.Delete(ctx, ref.URI)
}

// ---------------------------------------------------------------------------
// internal helpers
// ---------------------------------------------------------------------------

func (b *Backend) newHandle(meta cryptoenginesv2.KeyMetadata, uri string) (cryptoenginesv2.KeyHandle, error) {
	base := &handleBase{
		backend: b,
		meta:    meta,
		uri:     uri,
	}

	switch family := familyOfKeySpec(meta.KeySpec); family {
	case cryptoenginesv2.FamilyRSA:
		return &rsaHandle{handleBase: base}, nil
	case cryptoenginesv2.FamilyECDSA:
		// EC keys sign (ECDSA) and agree (ECDH) from the same handle.
		return &ecdsaHandle{handleBase: base}, nil
	// case cryptoenginesv2.FamilyEdDSA:
	// 	return &ed25519Handle{handleBase: base}, nil
	case cryptoenginesv2.FamilyECDH:
		return &ecdhHandle{handleBase: base}, nil
	case cryptoenginesv2.FamilyMLKEM:
		return &mlkemHandle{handleBase: base}, nil
	case cryptoenginesv2.FamilyAES:
		return &aesHandle{handleBase: base}, nil
	case cryptoenginesv2.FamilyHMAC:
		return &hmacHandle{handleBase: base}, nil
	default:
		return nil, fmt.Errorf("soft: unsupported key spec family %q for %s", family, meta.KeySpec)
	}
}

func blobURI(id cryptoenginesv2.KeyID) string { return "soft:blob/" + string(id) }

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

var randomReader = rand.Reader
