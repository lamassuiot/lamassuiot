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
	keySpec    cryptoenginesv2.KeySpec
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
			// One RSA-2048 key that signs (PKCS#1 v1.5 AND PSS), encrypts and
			// wraps — the AWS-KMS reuse model in action.
			name:    "RSA-2048 multi-algorithm (PKCS1v15 + PSS + OAEP)",
			keySpec: cryptoenginesv2.KeySpecRSA2048,
			operations: []cryptoenginesv2.Operation{
				cryptoenginesv2.OpSign, cryptoenginesv2.OpVerify,
				cryptoenginesv2.OpEncrypt, cryptoenginesv2.OpDecrypt,
				cryptoenginesv2.OpWrapKey, cryptoenginesv2.OpUnwrapKey,
			},
			verify: verifyRSAMultiAlgorithm,
		},
		{
			// One EC P-256 key that both signs (ECDSA) and agrees (ECDH).
			name:    "ECC P-256 sign + agree",
			keySpec: cryptoenginesv2.KeySpecECCNISTP256,
			operations: []cryptoenginesv2.Operation{
				cryptoenginesv2.OpSign, cryptoenginesv2.OpVerify,
				cryptoenginesv2.OpAgreeKey, cryptoenginesv2.OpDeriveKey,
			},
			verify: verifyECMultiUse,
		},
		{
			name:    "ECDSA P-384 signing",
			keySpec: cryptoenginesv2.KeySpecECCNISTP384,
			operations: []cryptoenginesv2.Operation{
				cryptoenginesv2.OpSign,
			},
			verify: verifyECDSASignSHA384,
		},
		{
			name:    "AES-GCM encrypt and decrypt",
			keySpec: cryptoenginesv2.KeySpecSymmetricDefault,
			operations: []cryptoenginesv2.Operation{
				cryptoenginesv2.OpEncrypt,
				cryptoenginesv2.OpDecrypt,
			},
			verify: verifyAESGCMRoundTrip,
		},
		{
			name:    "ML-KEM decapsulation",
			keySpec: cryptoenginesv2.KeySpecMLKEM768,
			operations: []cryptoenginesv2.Operation{
				cryptoenginesv2.OpEncapsulate,
				cryptoenginesv2.OpDecapsulate,
			},
			verify: verifyMLKEMRoundTrip,
		},
		{
			name:    "HMAC-SHA-256 compute and verify",
			keySpec: cryptoenginesv2.KeySpecHMAC256,
			operations: []cryptoenginesv2.Operation{
				cryptoenginesv2.OpMAC,
				cryptoenginesv2.OpVerifyMAC,
			},
			verify: verifyHMACSHA256,
		},
	}

	for _, tc := range cases {
		fmt.Printf("\n== %s ==\n", tc.name)

		key, err := svc.CreateKey(ctx, cryptoenginesv2.CreateKeySpec{
			KeySpec:    tc.keySpec,
			Operations: tc.operations,
		})
		if err != nil {
			fmt.Printf("CreateKey error: %v\n", err)
			continue
		}

		fmt.Printf("Created key with ID: %s and key spec: %s\n", key.Metadata().KeyID, key.Metadata().KeySpec)
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

// verifyRSAMultiAlgorithm proves the AWS-KMS reuse model: a single RSA-2048
// key signs with PKCS#1 v1.5 AND PSS, and decrypts an OAEP ciphertext — the
// per-operation algorithm is chosen at call time.
func verifyRSAMultiAlgorithm(ctx context.Context, key cryptoenginesv2.KeyHandle) error {
	signer, ok := key.(cryptoenginesv2.Signer)
	if !ok {
		return fmt.Errorf("key does not implement Signer")
	}
	pub, ok := key.Metadata().PublicKey.(*rsa.PublicKey)
	if !ok || pub == nil {
		return fmt.Errorf("missing RSA public key")
	}

	// 1) PKCS#1 v1.5 signature.
	sum := sha256.Sum256([]byte("hello RSA PKCS1v15"))
	sig, err := signer.SignContext(ctx, sum[:], cryptoenginesv2.AlgRSASSAPKCS1V15SHA256, crypto.SHA256)
	if err != nil {
		return fmt.Errorf("pkcs1v15 sign: %w", err)
	}
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
		return fmt.Errorf("pkcs1v15 verify: %w", err)
	}
	fmt.Printf("PKCS1v15 signature: %s\n", hexShort(sig))

	// 2) PSS signature (SHA-512) — same key, different algorithm.
	sum512 := sha512.Sum512([]byte("hello RSA PSS"))
	pssOpts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA512}
	sig, err = signer.SignContext(ctx, sum512[:], cryptoenginesv2.AlgRSASSAPSSSHA512, pssOpts)
	if err != nil {
		return fmt.Errorf("pss sign: %w", err)
	}
	if err := rsa.VerifyPSS(pub, crypto.SHA512, sum512[:], sig, pssOpts); err != nil {
		return fmt.Errorf("pss verify: %w", err)
	}
	fmt.Printf("PSS-SHA512 signature: %s\n", hexShort(sig))

	// 3) OAEP encrypt/decrypt — same key, encryption algorithm.
	encrypter := key.(cryptoenginesv2.Encrypter)
	decrypter := key.(cryptoenginesv2.Decrypter)
	plaintext := []byte("hello OAEP")
	ciphertext, err := encrypter.EncryptContext(ctx, plaintext, cryptoenginesv2.AlgRSAESOAEPSHA256, cryptoenginesv2.EncryptOpts{Hash: crypto.SHA256})
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}
	decrypted, err := decrypter.DecryptContext(ctx, ciphertext, cryptoenginesv2.AlgRSAESOAEPSHA256, &rsa.OAEPOptions{Hash: crypto.SHA256})
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		return fmt.Errorf("decrypt mismatch")
	}
	fmt.Printf("OAEP round-trip: %s\n", decrypted)
	return nil
}

// verifyECMultiUse proves one EC key does both ECDSA signing and ECDH agreement.
func verifyECMultiUse(ctx context.Context, key cryptoenginesv2.KeyHandle) error {
	signer, ok := key.(cryptoenginesv2.Signer)
	if !ok {
		return fmt.Errorf("key does not implement Signer")
	}
	agreementer, ok := key.(cryptoenginesv2.KeyAgreementer)
	if !ok {
		return fmt.Errorf("key does not implement KeyAgreementer")
	}
	pub, ok := key.Metadata().PublicKey.(*ecdsa.PublicKey)
	if !ok || pub == nil {
		return fmt.Errorf("missing ECDSA public key")
	}

	// ECDSA signature.
	sum := sha256.Sum256([]byte("hello ecdsa p256"))
	sig, err := signer.SignContext(ctx, sum[:], cryptoenginesv2.AlgECDSASHA256, nil)
	if err != nil {
		return fmt.Errorf("ecdsa sign: %w", err)
	}
	if !ecdsa.VerifyASN1(pub, sum[:], sig) {
		return fmt.Errorf("ecdsa verification failed")
	}
	fmt.Printf("ECDSA signature: %s\n", hexShort(sig))

	// ECDH agreement on the SAME key.
	peerPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate peer key: %w", err)
	}
	shared, err := agreementer.Agree(ctx, peerPriv.PublicKey(), cryptoenginesv2.AlgECDH)
	if err != nil {
		return fmt.Errorf("agree: %w", err)
	}
	ecdhPub, err := pub.ECDH()
	if err != nil {
		return fmt.Errorf("convert pub to ECDH: %w", err)
	}
	peerShared, err := peerPriv.ECDH(ecdhPub)
	if err != nil {
		return fmt.Errorf("peer ECDH: %w", err)
	}
	if !bytes.Equal(shared, peerShared) {
		return fmt.Errorf("shared secret mismatch")
	}
	fmt.Printf("ECDH shared secret: %s\n", hexShort(shared))
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

func verifyECDSASignSHA384(ctx context.Context, key cryptoenginesv2.KeyHandle) error {
	signer, ok := key.(cryptoenginesv2.Signer)
	if !ok {
		return fmt.Errorf("key does not implement Signer")
	}

	sum := sha512.Sum384([]byte("hello ecdsa p384"))
	signature, err := signer.SignContext(ctx, sum[:], cryptoenginesv2.AlgECDSASHA384, nil)
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
	ciphertext, err := cipherHandle.Encrypt(ctx, plaintext, cryptoenginesv2.AlgSymmetricDefault, opts)
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
	mac, err := macer.MAC(ctx, msg, cryptoenginesv2.AlgHMACSHA256)
	if err != nil {
		return fmt.Errorf("MAC: %w", err)
	}

	if err := macer.VerifyMAC(ctx, msg, mac, cryptoenginesv2.AlgHMACSHA256); err != nil {
		return fmt.Errorf("VerifyMAC: %w", err)
	}

	// Tampered message must fail verification.
	tampered := append([]byte(nil), msg...)
	tampered[0] ^= 0xff
	if err := macer.VerifyMAC(ctx, tampered, mac, cryptoenginesv2.AlgHMACSHA256); err == nil {
		return fmt.Errorf("VerifyMAC accepted tampered message")
	}

	fmt.Printf("msg: %s\n", msg)
	fmt.Printf("MAC: %s\n", hexShort(mac))
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
