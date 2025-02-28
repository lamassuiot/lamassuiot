package services

import (
	"context"
	"crypto/sha512"
	"crypto/x509"
	"fmt"
	"os"
	"testing"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/engines/crypto/filesystem/v3"
)

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
	filesystem.Register()
	tempDir := t.TempDir()
	log := chelpers.SetupLogger(config.Info, "Test Case", "Golang Engine")
	conf := config.CryptoEngineConfig{
		ID:       "test-engine",
		Type:     config.FilesystemProvider,
		Metadata: map[string]interface{}{},
		Config: map[string]interface{}{
			"storage_directory": tempDir,
		},
	}

	builder := cryptoengines.GetEngineBuilder(config.FilesystemProvider)
	engine, _ := builder(log, conf)

	defer os.RemoveAll(tempDir)

	kms := AsymmetricKMSServiceBackend{
		cryptoEngines: map[string]*cryptoengines.CryptoEngine{
			"test-engine": &engine,
		},
		defaultCryptoEngine:   &engine,
		defaultCryptoEngineID: "test-engine",
		logger:                log,
		kmsStore:              nil,
	}

	ecdsaKP, err := kms.CreateKeyPair(context.Background(), services.CreateKeyPairInput{
		EngineID:  "test-engine",
		Algorithm: x509.ECDSA,
		KeySize:   256,
	})
	if err != nil {
		t.Fatalf("failed to generate and import CA: %s", err)
	}

	rsaKP, err := kms.CreateKeyPair(context.Background(), services.CreateKeyPairInput{
		Algorithm: x509.RSA,
		KeySize:   2048,
	})
	if err != nil {
		t.Fatalf("failed to generate and import CA: %s", err)
	}

	if err != nil {
		t.Fatalf("failed to generate and import CA: %s", err)
	}

	notImportedKP := models.KeyPair{
		KeyID:     "not-imported",
		Algorithm: x509.RSA,
		KeySize:   2048,
	}

	// Create a sample message
	message := []byte("Hello, World!")

	var testcases = []struct {
		name             string
		kp               models.KeyPair
		msgType          models.SignMessageType
		signingAlgorithm x509.SignatureAlgorithm
		verifyAlgorithm  x509.SignatureAlgorithm
		value            func() ([]byte, error)
		check            func(validationResult bool, signatureError error, validationError error) error
	}{
		{
			name:             "OK/RSASSA_PSS_SHA_256",
			kp:               *rsaKP,
			msgType:          models.Raw,
			signingAlgorithm: x509.SHA256WithRSAPSS,
			check:            checkValidSignature,
		},
		{
			name:             "OK/RSASSA_PKCS1_V1_5_SHA_256",
			kp:               *rsaKP,
			msgType:          models.Raw,
			signingAlgorithm: x509.SHA256WithRSA,
			check:            checkValidSignature,
		},
		{
			name:             "OK/RSASSA_PSS_SHA_384",
			kp:               *rsaKP,
			msgType:          models.Raw,
			signingAlgorithm: x509.SHA384WithRSAPSS,
			check:            checkValidSignature,
		},
		{
			name:             "OK/RSASSA_PKCS1_V1_5_SHA_384",
			kp:               *rsaKP,
			msgType:          models.Raw,
			signingAlgorithm: x509.SHA384WithRSA,
			check:            checkValidSignature,
		},
		{
			name:             "OK/RSASSA_PSS_SHA_512",
			kp:               *rsaKP,
			msgType:          models.Raw,
			signingAlgorithm: x509.SHA512WithRSAPSS,
			check:            checkValidSignature,
		},
		{
			name:             "OK/RSASSA_PKCS1_V1_5_SHA_512",
			kp:               *rsaKP,
			msgType:          models.Raw,
			signingAlgorithm: x509.SHA512WithRSA,
			check:            checkValidSignature,
		},
		{
			name:             "OK/ECDSA_SHA_256",
			kp:               *ecdsaKP,
			msgType:          models.Raw,
			signingAlgorithm: x509.ECDSAWithSHA256,
			check:            checkValidSignature,
		},
		{
			name:             "OK/ECDSA_SHA_384",
			kp:               *ecdsaKP,
			msgType:          models.Raw,
			signingAlgorithm: x509.ECDSAWithSHA384,
			check:            checkValidSignature,
		},
		{
			name:             "OK/ECDSA_SHA_512",
			kp:               *ecdsaKP,
			msgType:          models.Raw,
			signingAlgorithm: x509.ECDSAWithSHA512,
			check:            checkValidSignature,
		},
		{
			name:             "OK/DIGEST/RSASSA_PSS_SHA_512",
			kp:               *rsaKP,
			msgType:          models.Hashed,
			signingAlgorithm: x509.SHA512WithRSAPSS,
			check:            checkValidSignature,
			value: func() ([]byte, error) {
				h := sha512.New()
				h.Write(message)
				return h.Sum(nil), nil
			},
		},
		{
			name:             "OK/DIGEST/ECDSA_SHA_512",
			kp:               *ecdsaKP,
			msgType:          models.Hashed,
			signingAlgorithm: x509.ECDSAWithSHA512,
			check:            checkValidSignature,
			value: func() ([]byte, error) {
				h := sha512.New()
				h.Write(message)
				return h.Sum(nil), nil
			},
		},
		{
			name:             "FAIL/RSA_WITH_ECDSA_CA",
			kp:               *ecdsaKP,
			msgType:          models.Raw,
			signingAlgorithm: x509.SHA256WithRSA,
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
			kp:               *rsaKP,
			msgType:          models.Raw,
			signingAlgorithm: x509.SHA256WithRSA,
			verifyAlgorithm:  x509.SHA384WithRSA,
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
			name:             "FAIL/UNKNOWN_CA",
			kp:               notImportedKP,
			msgType:          models.Raw,
			signingAlgorithm: x509.SHA256WithRSA,
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
			signature, errSignature := kms.Sign(ctx, services.KMSSignInput{
				KeyID:              tc.kp.KeyID,
				Message:            value,
				MessageType:        tc.msgType,
				SignatureAlgorithm: tc.signingAlgorithm,
			})

			verifyAlgorithm := tc.signingAlgorithm
			if tc.verifyAlgorithm != 0 {
				verifyAlgorithm = tc.verifyAlgorithm
			}

			// Call the Verify method
			val, errValidation := kms.Verify(ctx, services.VerifyInput{
				KeyID:              tc.kp.KeyID,
				Message:            value,
				MessageType:        tc.msgType,
				SignatureAlgorithm: verifyAlgorithm,
				Signature:          signature,
			})

			err := tc.check(val, errSignature, errValidation)
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}
		})
	}

}
