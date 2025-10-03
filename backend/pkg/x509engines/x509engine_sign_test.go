package x509engines

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"fmt"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
)

func generateAndImportCA(keyType x509.PublicKeyAlgorithm, engine cryptoengines.CryptoEngine) (*x509.Certificate, any, error) {
	caCertificate, key, err := chelpers.GenerateSelfSignedCA(keyType, 365*24*time.Hour, "MyCA")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate self signed CA: %s", err)
	}

	switch keyType {
	case x509.RSA:
		rsaPrivateKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, nil, fmt.Errorf("private key is not of type rsa.PrivateKey")
		}

		_, key, err = engine.ImportRSAPrivateKey(rsaPrivateKey)
		return caCertificate, key, err
	case x509.ECDSA:
		ecdsaPrivateKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, nil, fmt.Errorf("private key is not of type ecdsa.PrivateKey")
		}

		_, key, err := engine.ImportECDSAPrivateKey(ecdsaPrivateKey)
		return caCertificate, key, err
	case x509.MLDSA:
		mldsaKey, ok := key.(crypto.Signer)
		if !ok {
			return nil, nil, fmt.Errorf("private key is not of type mldsaXX.PrivateKey")
		}

		_, key, err := engine.ImportMLDSAPrivateKey(mldsaKey)
		return caCertificate, key, err
	case x509.Ed25519:
		ed25519Key, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, nil, fmt.Errorf("private key is not of type ed25519.PrivateKey")
		}

		_, key, err := engine.ImportEd25519PrivateKey(ed25519Key)
		return caCertificate, key, err
	default:
		return nil, nil, fmt.Errorf("unsupported key type")
	}
}

func checkValidSignature(validationResult bool, signatureError error, validationError error) error {

	if signatureError != nil {
		return fmt.Errorf("unexpected signature error %s", signatureError)
	}
	if validationError != nil {
		return fmt.Errorf("unexpected validation error %s", validationError)
	}
	if !validationResult {
		return fmt.Errorf("unexpected signature validation result, expected true, got false")
	}

	return nil
}

func TestSignVerify(t *testing.T) {
	tempDir, engine, x509Engine := setup(t)
	defer teardown(tempDir)

	caCertificateRSA, _, err := generateAndImportCA(x509.RSA, engine)
	if err != nil {
		t.Fatalf("failed to generate and import CA: %s", err)
	}

	caCertificateECDSA, _, err := generateAndImportCA(x509.ECDSA, engine)
	if err != nil {
		t.Fatalf("failed to generate and import CA: %s", err)
	}

	caCertificateMLDSA, _, err := generateAndImportCA(x509.MLDSA, engine)
	if err != nil {
		t.Fatalf("failed to generate and import CA: %s", err)
	}

	caCertificateEd25519, _, err := generateAndImportCA(x509.Ed25519, engine)
	if err != nil {
		t.Fatalf("failed to generate and import CA: %s", err)
	}

	if err != nil {
		t.Fatalf("failed to generate and import CA: %s", err)
	}

	caCertificateNotImported, _, err := chelpers.GenerateSelfSignedCA(x509.ECDSA, 365*24*time.Hour, "MyCA")
	if err != nil {
		t.Fatalf("failed to generate self signed CA: %s", err)
	}

	// Create a sample message
	message := []byte("Hello, World!")

	var testcases = []struct {
		name             string
		certificate      *x509.Certificate
		msgType          models.SignMessageType
		signingAlgorithm string
		verifyAlgorithm  string
		value            func() ([]byte, error)
		check            func(validationResult bool, signatureError error, validationError error) error
	}{
		{
			name:             "OK/RSASSA_PSS_SHA_256",
			certificate:      caCertificateRSA,
			msgType:          models.Raw,
			signingAlgorithm: "RSASSA_PSS_SHA_256",
			check:            checkValidSignature,
		},
		{
			name:             "OK/RSASSA_PKCS1_V1_5_SHA_256",
			certificate:      caCertificateRSA,
			msgType:          models.Raw,
			signingAlgorithm: "RSASSA_PKCS1_V1_5_SHA_256",
			check:            checkValidSignature,
		},
		{
			name:             "OK/RSASSA_PSS_SHA_384",
			certificate:      caCertificateRSA,
			msgType:          models.Raw,
			signingAlgorithm: "RSASSA_PSS_SHA_384",
			check:            checkValidSignature,
		},
		{
			name:             "OK/RSASSA_PKCS1_V1_5_SHA_384",
			certificate:      caCertificateRSA,
			msgType:          models.Raw,
			signingAlgorithm: "RSASSA_PKCS1_V1_5_SHA_384",
			check:            checkValidSignature,
		},
		{
			name:             "OK/RSASSA_PSS_SHA_512",
			certificate:      caCertificateRSA,
			msgType:          models.Raw,
			signingAlgorithm: "RSASSA_PSS_SHA_512",
			check:            checkValidSignature,
		},
		{
			name:             "OK/RSASSA_PKCS1_V1_5_SHA_512",
			certificate:      caCertificateRSA,
			msgType:          models.Raw,
			signingAlgorithm: "RSASSA_PKCS1_V1_5_SHA_512",
			check:            checkValidSignature,
		},
		{
			name:             "OK/ECDSA_SHA_256",
			certificate:      caCertificateECDSA,
			msgType:          models.Raw,
			signingAlgorithm: "ECDSA_SHA_256",
			check:            checkValidSignature,
		},
		{
			name:             "OK/ECDSA_SHA_384",
			certificate:      caCertificateECDSA,
			msgType:          models.Raw,
			signingAlgorithm: "ECDSA_SHA_384",
			check:            checkValidSignature,
		},
		{
			name:             "OK/ECDSA_SHA_512",
			certificate:      caCertificateECDSA,
			msgType:          models.Raw,
			signingAlgorithm: "ECDSA_SHA_512",
			check:            checkValidSignature,
		},
		{
			name:        "OK/MLDSA_PURE",
			certificate: caCertificateMLDSA,
			msgType:     models.Raw,
			check:       checkValidSignature,
		},
		{
			name:        "OK/Ed25519_PURE",
			certificate: caCertificateEd25519,
			msgType:     models.Raw,
			check:       checkValidSignature,
		},
		{
			name:             "OK/DIGEST/RSASSA_PSS_SHA_512",
			certificate:      caCertificateRSA,
			msgType:          models.Hashed,
			signingAlgorithm: "RSASSA_PSS_SHA_512",
			check:            checkValidSignature,
			value: func() ([]byte, error) {
				h := sha512.New()
				h.Write(message)
				return h.Sum(nil), nil
			},
		},
		{
			name:             "OK/DIGEST/ECDSA_SHA_512",
			certificate:      caCertificateECDSA,
			msgType:          models.Hashed,
			signingAlgorithm: "ECDSA_SHA_512",
			check:            checkValidSignature,
			value: func() ([]byte, error) {
				h := sha512.New()
				h.Write(message)
				return h.Sum(nil), nil
			},
		},
		{
			name:             "FAIL/ECDSA_UNKNOWN",
			certificate:      caCertificateECDSA,
			msgType:          models.Raw,
			signingAlgorithm: "ECDSA_UNKNOWN",
			check: func(validationResult bool, signatureError, validationError error) error {
				if signatureError == nil {
					return fmt.Errorf("expected signature error, got nil")
				}
				if validationError == nil {
					return fmt.Errorf("expected validation error, got nil")
				}
				return nil
			},
		},
		{
			name:             "FAIL/RSA_UNKNOWN",
			certificate:      caCertificateRSA,
			msgType:          models.Raw,
			signingAlgorithm: "RSA_UNKNOWN",
			check: func(validationResult bool, signatureError, validationError error) error {
				if signatureError == nil {
					return fmt.Errorf("expected signature error, got nil")
				}
				if validationError == nil {
					return fmt.Errorf("expected validation error, got nil")
				}
				return nil
			},
		},
		{
			name:             "FAIL/RSA_WITH_ECDSA_CA",
			certificate:      caCertificateECDSA,
			msgType:          models.Raw,
			signingAlgorithm: "RSASSA_PSS_SHA_512",
			check: func(validationResult bool, signatureError, validationError error) error {
				if signatureError == nil {
					return fmt.Errorf("expected signature error, got nil")
				}
				if validationError == nil {
					return fmt.Errorf("expected validation error, got nil")
				}
				return nil
			},
		},
		{
			name:             "FAIL/SIGN_AND_VERIFY_WITH_DIFFERENT_ALGORITHMS",
			certificate:      caCertificateRSA,
			msgType:          models.Raw,
			signingAlgorithm: "RSASSA_PSS_SHA_256",
			verifyAlgorithm:  "RSASSA_PSS_SHA_384",
			check: func(validationResult bool, signatureError, validationError error) error {
				if signatureError != nil {
					return fmt.Errorf("unexpected signature error %s", signatureError)
				}
				if validationError == nil {
					return fmt.Errorf("expected validation error, got nil")
				}

				if validationResult {
					return fmt.Errorf("unexpected signature validation result, expected false, got true")
				}

				return nil
			},
		},
		{
			name:             "FAIL/UNKOWN_CA",
			certificate:      caCertificateNotImported,
			msgType:          models.Raw,
			signingAlgorithm: "RSASSA_PSS_SHA_256",
			check: func(validationResult bool, signatureError, validationError error) error {
				if signatureError == nil {
					return fmt.Errorf("expected signature error, got nil")
				}
				if validationError == nil {
					return fmt.Errorf("expected validation error, got nil")
				}
				return nil
			},
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {

			value := message
			if tc.value != nil {
				value, err = tc.value()
				if err != nil {
					t.Fatalf("failed to generate value: %s", err)
				}
			}

			ctx := context.Background()
			// Call the Sign method
			signature, errSignature := x509Engine.Sign(ctx, tc.certificate, value, tc.msgType, tc.signingAlgorithm)
			verifyAlgorithm := tc.signingAlgorithm
			if tc.verifyAlgorithm != "" {
				verifyAlgorithm = tc.verifyAlgorithm
			}
			val, errValidation := x509Engine.Verify(ctx, tc.certificate, signature, value, tc.msgType, verifyAlgorithm)
			err := tc.check(val, errSignature, errValidation)
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}
		})
	}

}
