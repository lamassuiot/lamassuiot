package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"os"

	cryptoenginesv2 "github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines_v2"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines_v2/backendregistry"
	cryptoregistry "github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines_v2/registry"
	metamemory "github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines_v2/store/memory"
	"github.com/lamassuiot/lamassuiot/engines/crypto/softwarev2/v3"
	"gocloud.dev/blob"
	_ "gocloud.dev/blob/fileblob"
)

type algorithmCase struct {
	name       string
	algorithm  cryptoenginesv2.AlgorithmID
	operations []cryptoenginesv2.Operation
	verify     func(context.Context, cryptoenginesv2.KeyHandle) error
}

func main() {
	svc, err := setup()
	if err != nil {
		panic(err)
	}

	ctx := context.Background()
	cases := []algorithmCase{
		{
			name:      "RSA PKCS#1 v1.5 signing",
			algorithm: "RSASSA_PKCS1_V1_5_SHA_256",
			operations: []cryptoenginesv2.Operation{
				cryptoenginesv2.OpSign,
			},
			verify: verifySignSHA256,
		},
		{
			name:      "RSA PSS signing",
			algorithm: "RSASSA_PSS_SHA_256",
			operations: []cryptoenginesv2.Operation{
				cryptoenginesv2.OpSign,
			},
			verify: verifyRSAPSSSignSHA256,
		},
		{
			name:      "RSA OAEP wrap and decrypt",
			algorithm: "RSAES_OAEP_SHA_256_2048",
			operations: []cryptoenginesv2.Operation{
				cryptoenginesv2.OpEncrypt,
				cryptoenginesv2.OpDecrypt,
				cryptoenginesv2.OpWrapKey,
				cryptoenginesv2.OpUnwrapKey,
			},
			verify: verifyRSAOAEPWrapAndDecrypt,
		},
		{
			name:      "ECDSA P-256 signing",
			algorithm: "ECDSA_SHA_256",
			operations: []cryptoenginesv2.Operation{
				cryptoenginesv2.OpSign,
			},
			verify: verifyECDSASignSHA256,
		},
		{
			name:      "ECDSA P-384 signing",
			algorithm: "ECDSA_SHA_384",
			operations: []cryptoenginesv2.Operation{
				cryptoenginesv2.OpSign,
			},
			verify: verifyECDSASignSHA384,
		},
		{
			name:      "AES-GCM encrypt and decrypt",
			algorithm: "AES_GCM_256",
			operations: []cryptoenginesv2.Operation{
				cryptoenginesv2.OpEncrypt,
				cryptoenginesv2.OpDecrypt,
			},
			verify: verifyAESGCMRoundTrip,
		},
		{
			name:      "ML-KEM decapsulation",
			algorithm: "ML_KEM_768",
			operations: []cryptoenginesv2.Operation{
				cryptoenginesv2.OpEncapsulate,
				cryptoenginesv2.OpDecapsulate,
			},
			verify: verifyMLKEMRoundTrip,
		},
		{
			name:      "HMAC-SHA-256 compute and verify",
			algorithm: "HMAC_SHA_256",
			operations: []cryptoenginesv2.Operation{
				cryptoenginesv2.OpMAC,
				cryptoenginesv2.OpVerifyMAC,
			},
			verify: verifyHMACSHA256,
		},
		{
			name:      "ECDH P-256 key agreement",
			algorithm: "ECDH_NIST_P256",
			operations: []cryptoenginesv2.Operation{
				cryptoenginesv2.OpAgreeKey,
			},
			verify: verifyECDHP256Agree,
		},
	}

	for _, tc := range cases {
		fmt.Printf("\n== %s ==\n", tc.name)

		key, err := svc.CreateKey(ctx, cryptoenginesv2.CreateKeySpec{
			Algorithm:  tc.algorithm,
			Operations: tc.operations,
		})
		if err != nil {
			fmt.Printf("CreateKey error: %v\n", err)
			continue
		}

		fmt.Printf("Created key with ID: %s and algorithm: %s\n", key.Metadata().KeyID, key.Metadata().Algorithm)
		printCapabilities(key)

		if tc.verify == nil {
			fmt.Println("basic operation: skipped")
			continue
		}

		if err := tc.verify(ctx, key); err != nil {
			fmt.Printf("basic operation: ERROR: %v\n", err)
			continue
		}
		fmt.Println("basic operation: OK")
	}
}

func printCapabilities(key cryptoenginesv2.KeyHandle) {
	ops := key.Metadata().Operations

	fmt.Println("signer support:", supported(okSigner(key) && hasOperation(ops, cryptoenginesv2.OpSign)))
	fmt.Println("encrypter support:", supported(okEncrypter(key) && hasOperation(ops, cryptoenginesv2.OpEncrypt)))
	fmt.Println("decrypter support:", supported(okDecrypter(key) && hasOperation(ops, cryptoenginesv2.OpDecrypt)))
	fmt.Println("encapsulator support:", supported(okEncapsulator(key) && hasOperation(ops, cryptoenginesv2.OpEncapsulate)))
	fmt.Println("decapsulator support:", supported(okDecapsulator(key) && hasOperation(ops, cryptoenginesv2.OpDecapsulate)))
	fmt.Println("key wrapper support:", supported(okKeyWrapper(key) && hasOperation(ops, cryptoenginesv2.OpWrapKey)))
	fmt.Println("symmetric cipher support:", supported(okSymmetricCipher(key) && hasOperation(ops, cryptoenginesv2.OpEncrypt)))
	fmt.Println("MACer support:", supported(okMACer(key) && hasOperation(ops, cryptoenginesv2.OpMAC)))
	fmt.Println("key agreement support:", supported(okKeyAgreementer(key) && hasOperation(ops, cryptoenginesv2.OpAgreeKey)))
}

func hexShort(b []byte) string {
	const show = 16
	if len(b) <= show {
		return hex.EncodeToString(b)
	}
	return hex.EncodeToString(b[:show]) + fmt.Sprintf("... (%d bytes)", len(b))
}

func supported(ok bool) string {
	if ok {
		return "✅"
	}
	return "❌"
}

func hasOperation(ops []cryptoenginesv2.Operation, target cryptoenginesv2.Operation) bool {
	for _, op := range ops {
		if op == target {
			return true
		}
	}
	return false
}

func okSigner(key cryptoenginesv2.KeyHandle) bool {
	_, ok := key.(cryptoenginesv2.Signer)
	return ok
}

func okDecrypter(key cryptoenginesv2.KeyHandle) bool {
	_, ok := key.(cryptoenginesv2.Decrypter)
	return ok
}

func okEncrypter(key cryptoenginesv2.KeyHandle) bool {
	_, ok := key.(cryptoenginesv2.Encrypter)
	return ok
}

func okEncapsulator(key cryptoenginesv2.KeyHandle) bool {
	_, ok := key.(cryptoenginesv2.Encapsulator)
	return ok
}

func okDecapsulator(key cryptoenginesv2.KeyHandle) bool {
	_, ok := key.(cryptoenginesv2.Decapsulator)
	return ok
}

func okKeyWrapper(key cryptoenginesv2.KeyHandle) bool {
	_, ok := key.(cryptoenginesv2.KeyWrapper)
	return ok
}

func okSymmetricCipher(key cryptoenginesv2.KeyHandle) bool {
	_, ok := key.(cryptoenginesv2.SymmetricCipher)
	return ok
}

func okMACer(key cryptoenginesv2.KeyHandle) bool {
	_, ok := key.(cryptoenginesv2.MACer)
	return ok
}

func okKeyAgreementer(key cryptoenginesv2.KeyHandle) bool {
	_, ok := key.(cryptoenginesv2.KeyAgreementer)
	return ok
}

func verifySignSHA256(ctx context.Context, key cryptoenginesv2.KeyHandle) error {
	signer, ok := key.(cryptoenginesv2.Signer)
	if !ok {
		return fmt.Errorf("key does not implement Signer")
	}

	msg := []byte("hello RSA PKCS1v15")
	sum := sha256.Sum256(msg)
	signature, err := signer.SignContext(ctx, sum[:], crypto.SHA256)
	if err != nil {
		return err
	}

	pub, ok := key.Metadata().PublicKey.(*rsa.PublicKey)
	if !ok || pub == nil {
		return fmt.Errorf("missing RSA public key")
	}
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], signature); err != nil {
		return fmt.Errorf("RSA PKCS1v15 verification failed: %w", err)
	}

	fmt.Printf("msg:       %s\n", msg)
	fmt.Printf("digest:    %s\n", hexShort(sum[:]))
	fmt.Printf("signature: %s\n", hexShort(signature))
	return nil
}

func verifyRSAPSSSignSHA256(ctx context.Context, key cryptoenginesv2.KeyHandle) error {
	signer, ok := key.(cryptoenginesv2.Signer)
	if !ok {
		return fmt.Errorf("key does not implement Signer")
	}

	msg := []byte("hello RSA PSS")
	sum := sha256.Sum256(msg)
	signature, err := signer.SignContext(ctx, sum[:], &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       crypto.SHA256,
	})
	if err != nil {
		return err
	}

	pub, ok := key.Metadata().PublicKey.(*rsa.PublicKey)
	if !ok || pub == nil {
		return fmt.Errorf("missing RSA public key")
	}
	if err := rsa.VerifyPSS(pub, crypto.SHA256, sum[:], signature, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       crypto.SHA256,
	}); err != nil {
		return fmt.Errorf("RSA PSS verification failed: %w", err)
	}

	fmt.Printf("msg:       %s\n", msg)
	fmt.Printf("digest:    %s\n", hexShort(sum[:]))
	fmt.Printf("signature: %s\n", hexShort(signature))
	return nil
}

func verifyRSAOAEPWrapAndDecrypt(ctx context.Context, key cryptoenginesv2.KeyHandle) error {
	wrapper, ok := key.(cryptoenginesv2.KeyWrapper)
	if !ok {
		return fmt.Errorf("key does not implement KeyWrapper")
	}
	encrypter, ok := key.(cryptoenginesv2.Encrypter)
	if !ok {
		return fmt.Errorf("key does not implement Encrypter")
	}
	decrypter, ok := key.(cryptoenginesv2.Decrypter)
	if !ok {
		return fmt.Errorf("key does not implement Decrypter")
	}

	plaintext := []byte("hello wrap")
	wrapped, err := wrapper.WrapKey(ctx, plaintext, cryptoenginesv2.WrapOpts{})
	if err != nil {
		return fmt.Errorf("wrap: %w", err)
	}

	unwrapped, err := wrapper.UnwrapKey(ctx, wrapped, cryptoenginesv2.WrapOpts{})
	if err != nil {
		return fmt.Errorf("unwrap: %w", err)
	}
	if !bytes.Equal(unwrapped, plaintext) {
		return fmt.Errorf("unwrap mismatch")
	}

	ciphertext, err := encrypter.EncryptContext(ctx, plaintext, cryptoenginesv2.EncryptOpts{
		Hash: crypto.SHA256,
	})
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}
	decrypted, err := decrypter.DecryptContext(ctx, ciphertext, &rsa.OAEPOptions{Hash: crypto.SHA256})
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		return fmt.Errorf("decrypt mismatch")
	}

	fmt.Printf("plaintext:  %s\n", plaintext)
	fmt.Printf("wrapped:    %s\n", hexShort(wrapped))
	fmt.Printf("ciphertext: %s\n", hexShort(ciphertext))
	fmt.Printf("decrypted:  %s\n", decrypted)
	return nil
}

func verifyMLKEMRoundTrip(ctx context.Context, key cryptoenginesv2.KeyHandle) error {
	encapsulator, ok := key.(cryptoenginesv2.Encapsulator)
	if !ok {
		return fmt.Errorf("key does not implement Encapsulator")
	}
	decapsulator, ok := key.(cryptoenginesv2.Decapsulator)
	if !ok {
		return fmt.Errorf("key does not implement Decapsulator")
	}

	sharedSecret, ciphertext, err := encapsulator.EncapsulateContext(ctx)
	if err != nil {
		return err
	}
	decapsulated, err := decapsulator.DecapsulateContext(ctx, ciphertext)
	if err != nil {
		return err
	}
	if !bytes.Equal(decapsulated, sharedSecret) {
		return fmt.Errorf("shared secret mismatch")
	}

	fmt.Printf("ciphertext:    %s\n", hexShort(ciphertext))
	fmt.Printf("shared secret: %s\n", hexShort(sharedSecret))
	return nil
}

func verifyECDSASignSHA256(ctx context.Context, key cryptoenginesv2.KeyHandle) error {
	signer, ok := key.(cryptoenginesv2.Signer)
	if !ok {
		return fmt.Errorf("key does not implement Signer")
	}

	sum := sha256.Sum256([]byte("hello ecdsa p256"))
	signature, err := signer.SignContext(ctx, sum[:], nil)
	if err != nil {
		return err
	}

	pub, ok := key.Metadata().PublicKey.(*ecdsa.PublicKey)
	if !ok || pub == nil {
		return fmt.Errorf("missing ECDSA public key")
	}
	if !ecdsa.VerifyASN1(pub, sum[:], signature) {
		return fmt.Errorf("ecdsa verification failed")
	}

	fmt.Printf("msg:       %s\n", []byte("hello ecdsa p256"))
	fmt.Printf("digest:    %s\n", hexShort(sum[:]))
	fmt.Printf("signature: %s\n", hexShort(signature))
	return nil
}

func verifyECDSASignSHA384(ctx context.Context, key cryptoenginesv2.KeyHandle) error {
	signer, ok := key.(cryptoenginesv2.Signer)
	if !ok {
		return fmt.Errorf("key does not implement Signer")
	}

	sum := sha512.Sum384([]byte("hello ecdsa p384"))
	signature, err := signer.SignContext(ctx, sum[:], nil)
	if err != nil {
		return err
	}

	pub, ok := key.Metadata().PublicKey.(*ecdsa.PublicKey)
	if !ok || pub == nil {
		return fmt.Errorf("missing ECDSA public key")
	}
	if !ecdsa.VerifyASN1(pub, sum[:], signature) {
		return fmt.Errorf("ecdsa verification failed")
	}

	fmt.Printf("msg:       %s\n", []byte("hello ecdsa p384"))
	fmt.Printf("digest:    %s\n", hexShort(sum[:]))
	fmt.Printf("signature: %s\n", hexShort(signature))
	return nil
}

func verifyAESGCMRoundTrip(ctx context.Context, key cryptoenginesv2.KeyHandle) error {
	cipherHandle, ok := key.(cryptoenginesv2.SymmetricCipher)
	if !ok {
		return fmt.Errorf("key does not implement SymmetricCipher")
	}

	plaintext := []byte("hello aes gcm")
	opts := cryptoenginesv2.SymmetricOpts{
		AssociatedData: []byte("demo-aad"),
	}
	ciphertext, err := cipherHandle.Encrypt(ctx, plaintext, opts)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	decrypted, err := cipherHandle.Decrypt(ctx, ciphertext, cryptoenginesv2.SymmetricOpts{
		AssociatedData: []byte("demo-aad"),
	})
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		return fmt.Errorf("aes round-trip mismatch")
	}

	fmt.Printf("plaintext:  %s\n", plaintext)
	fmt.Printf("nonce:      %s\n", hexShort(ciphertext.Nonce))
	fmt.Printf("ciphertext: %s\n", hexShort(ciphertext.Bytes))
	fmt.Printf("decrypted:  %s\n", decrypted)
	return nil
}

func verifyHMACSHA256(ctx context.Context, key cryptoenginesv2.KeyHandle) error {
	macer, ok := key.(cryptoenginesv2.MACer)
	if !ok {
		return fmt.Errorf("key does not implement MACer")
	}

	msg := []byte("hello HMAC SHA-256")
	mac, err := macer.MAC(ctx, msg)
	if err != nil {
		return fmt.Errorf("MAC: %w", err)
	}

	if err := macer.VerifyMAC(ctx, msg, mac); err != nil {
		return fmt.Errorf("VerifyMAC: %w", err)
	}

	// Tampered message must fail verification.
	tampered := append([]byte(nil), msg...)
	tampered[0] ^= 0xff
	if err := macer.VerifyMAC(ctx, tampered, mac); err == nil {
		return fmt.Errorf("VerifyMAC accepted tampered message")
	}

	fmt.Printf("msg: %s\n", msg)
	fmt.Printf("MAC: %s\n", hexShort(mac))
	return nil
}

func verifyECDHP256Agree(ctx context.Context, key cryptoenginesv2.KeyHandle) error {
	agreementer, ok := key.(cryptoenginesv2.KeyAgreementer)
	if !ok {
		return fmt.Errorf("key does not implement KeyAgreementer")
	}

	// Generate an ephemeral peer key locally to test interop.
	peerPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate peer key: %w", err)
	}

	shared, err := agreementer.Agree(ctx, peerPriv.PublicKey())
	if err != nil {
		return fmt.Errorf("Agree: %w", err)
	}

	// Verify from the peer's side using raw ECDH with the handle's public key.
	pub, ok := key.Metadata().PublicKey.(*ecdh.PublicKey)
	if !ok || pub == nil {
		return fmt.Errorf("missing ECDH public key")
	}
	peerShared, err := peerPriv.ECDH(pub)
	if err != nil {
		return fmt.Errorf("peer ECDH: %w", err)
	}

	if !bytes.Equal(shared, peerShared) {
		return fmt.Errorf("shared secret mismatch")
	}

	fmt.Printf("shared secret: %s\n", hexShort(shared))
	return nil
}

func setup() (cryptoenginesv2.Service, error) {
	if err := os.MkdirAll("/tmp/soft-blobs", 0700); err != nil {
		return nil, err
	}
	blobs, err := blob.OpenBucket(context.Background(), "file:///tmp/soft-blobs")
	if err != nil {
		return nil, err
	}

	backend, err := softwarev2.New(softwarev2.Options{Blobs: blobs})
	if err != nil {
		return nil, err
	}

	metadata := metamemory.New()
	registry := cryptoregistry.NewBuiltinRegistry()
	backendReg := backendregistry.NewSingleBackendRegistry(backend)

	return cryptoenginesv2.NewService(registry, metadata, backendReg), nil
}
