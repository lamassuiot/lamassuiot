package ca

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/backend/pkg/assemblers/tests"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	chelpers "github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/stretchr/testify/assert"
)

// A cross-signed CA is a second CA entry for an existing key pair, issued by another CA. Deleting
// it, or the CA it was issued for, must not delete the key the remaining entry still signs with.
func TestDeleteCrossSignedCAKeepsSharedKey(t *testing.T) {
	targets := map[string]func(t *testing.T, caTest *tests.CATestServer, profileID string) *models.CACertificate{
		"ManagedTarget": func(t *testing.T, caTest *tests.CATestServer, profileID string) *models.CACertificate {
			ca, err := caTest.Service.CreateCA(context.Background(), services.CreateCAInput{
				KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
				Subject:      models.Subject{CommonName: "CrossSignTarget"},
				CAExpiration: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour * 24)},
				ProfileID:    profileID,
			})
			if err != nil {
				t.Fatalf("could not create target CA: %s", err)
			}
			return ca
		},
		// Imported CAs keep the SKI they came with (a SHA-1 here), which differs from the KMS key ID
		// the cross certificate gets as its SKI.
		"ImportedWithKeyTarget": func(t *testing.T, caTest *tests.CATestServer, profileID string) *models.CACertificate {
			caCert, caKey, err := chelpers.GenerateSelfSignedCA(x509.RSA, time.Hour*24, "CrossSignImportedTarget")
			if err != nil {
				t.Fatalf("could not generate target CA: %s", err)
			}
			ca, err := caTest.Service.ImportCA(context.Background(), services.ImportCAInput{
				CACertificate: (*models.X509Certificate)(caCert),
				ProfileID:     profileID,
				Key:           caKey.(*rsa.PrivateKey),
			})
			if err != nil {
				t.Fatalf("could not import target CA: %s", err)
			}
			return ca
		},
	}

	for name, createTarget := range targets {
		t.Run(name, func(t *testing.T) {
			t.Run("DeleteCrossSignedCA", func(t *testing.T) {
				caTest, signer, target, cross, keyURI := setupCrossSign(t, createTarget)

				revokeAndDeleteCA(t, caTest, cross.ID, false)

				assertKeyExists(t, keyURI)
				assertKeyBindings(t, keyURI, target)
				assertCACanSign(t, caTest, target)
				assertCACanSign(t, caTest, signer)
			})

			// Keys bound before bindings were kept up to date may lack the other CA's binding.
			t.Run("DeleteCrossSignedCAWithoutBindings", func(t *testing.T) {
				caTest, _, target, cross, keyURI := setupCrossSign(t, createTarget)
				_, err := serverTest.KMS.Service.UnbindKeyResource(context.Background(), services.KeyResourceBindingInput{
					Identifier: keyURI,
					Resource:   models.KMSBindResource{ResourceType: models.KMSBindResourceTypeCertificate, ResourceID: target.Certificate.SerialNumber},
				})
				if err != nil {
					t.Fatalf("could not unbind target CA: %s", err)
				}

				revokeAndDeleteCA(t, caTest, cross.ID, false)

				assertKeyExists(t, keyURI)
				assertCACanSign(t, caTest, target)
			})

			t.Run("DeleteOriginalCA", func(t *testing.T) {
				caTest, _, target, cross, keyURI := setupCrossSign(t, createTarget)

				revokeAndDeleteCA(t, caTest, target.ID, false)

				assertKeyExists(t, keyURI)
				assertKeyBindings(t, keyURI, cross)
				assertCACanSign(t, caTest, cross)
			})

			t.Run("CascadeDeleteSigner", func(t *testing.T) {
				caTest, signer, target, cross, keyURI := setupCrossSign(t, createTarget)

				revokeAndDeleteCA(t, caTest, signer.ID, true)

				verifyCADeleted(t, caTest, cross.ID, "cross-signed CA")
				assertKeyExists(t, keyURI)
				assertKeyBindings(t, keyURI, target)
				assertCACanSign(t, caTest, target)
			})

			t.Run("DeleteBothCAs", func(t *testing.T) {
				caTest, _, target, cross, keyURI := setupCrossSign(t, createTarget)

				revokeAndDeleteCA(t, caTest, cross.ID, false)
				revokeAndDeleteCA(t, caTest, target.ID, false)

				_, err := serverTest.KMS.Service.GetKey(context.Background(), services.GetKeyInput{Identifier: keyURI})
				if err == nil {
					t.Fatalf("key %s should be deleted once no CA uses it", keyURI)
				}
			})
		})
	}
}

func TestImportCAWithMismatchedKeyFails(t *testing.T) {
	if err := serverTest.BeforeEach(); err != nil {
		t.Fatalf("failed running 'BeforeEach' cleanup func: %s", err)
	}

	caCert, _, err := chelpers.GenerateSelfSignedCA(x509.RSA, time.Hour*24, "MismatchedKeyCA")
	if err != nil {
		t.Fatalf("could not generate CA: %s", err)
	}
	otherKey, err := chelpers.GenerateRSAKey(2048)
	if err != nil {
		t.Fatalf("could not generate key: %s", err)
	}

	_, err = serverTest.CA.Service.ImportCA(context.Background(), services.ImportCAInput{
		CACertificate: (*models.X509Certificate)(caCert),
		Key:           otherKey,
	})
	if err != errs.ErrValidateBadRequest {
		t.Fatalf("importing a CA with a key that does not match its certificate should fail with %s, got: %v", errs.ErrValidateBadRequest, err)
	}
}

// setupCrossSign creates a signer root CA, a target CA and a cross-signed CA for the target's key
// issued by the signer, the way the dashboard does it. It returns the PKCS#11 URI of the shared key.
func setupCrossSign(t *testing.T, createTarget func(*testing.T, *tests.CATestServer, string) *models.CACertificate) (*tests.CATestServer, *models.CACertificate, *models.CACertificate, *models.CACertificate, string) {
	t.Helper()
	if err := serverTest.BeforeEach(); err != nil {
		t.Fatalf("failed running 'BeforeEach' cleanup func: %s", err)
	}
	caTest := serverTest.CA
	ctx := context.Background()

	profile, err := caTest.Service.CreateIssuanceProfile(ctx, services.CreateIssuanceProfileInput{
		Profile: models.IssuanceProfile{
			Validity: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour)},
		},
	})
	if err != nil {
		t.Fatalf("could not create issuance profile: %s", err)
	}

	signer, err := caTest.Service.CreateCA(ctx, services.CreateCAInput{
		KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
		Subject:      models.Subject{CommonName: "CrossSignSigner"},
		CAExpiration: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour * 24)},
		ProfileID:    profile.ID,
	})
	if err != nil {
		t.Fatalf("could not create signer CA: %s", err)
	}

	target := createTarget(t, caTest, profile.ID)

	// The KMS key ID is the hex SHA-256 of the DER SubjectPublicKeyInfo.
	spki, err := x509.MarshalPKIXPublicKey(target.Certificate.Certificate.PublicKey)
	if err != nil {
		t.Fatalf("could not marshal target public key: %s", err)
	}
	digest := sha256.Sum256(spki)
	keyID := hex.EncodeToString(digest[:])

	cross, err := caTest.Service.CreateCA(ctx, services.CreateCAInput{
		ParentID:     signer.ID,
		EngineID:     target.Certificate.EngineID,
		KeyMetadata:  models.KeyMetadata{KeyID: keyID},
		Subject:      target.Certificate.Subject,
		CAExpiration: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour * 12)},
		ProfileID:    profile.ID,
	})
	if err != nil {
		t.Fatalf("could not cross-sign target CA: %s", err)
	}

	keyURI := fmt.Sprintf("pkcs11:token-id=%s;id=%s;type=private", target.Certificate.EngineID, keyID)
	assertKeyExists(t, keyURI)
	assertKeyBindings(t, keyURI, target, cross)
	assertCACanSign(t, caTest, target)
	assertCACanSign(t, caTest, cross)

	return caTest, signer, target, cross, keyURI
}

func revokeAndDeleteCA(t *testing.T, caTest *tests.CATestServer, caID string, cascade bool) {
	t.Helper()
	_, err := caTest.Service.UpdateCAStatus(context.Background(), services.UpdateCAStatusInput{
		CAID:             caID,
		Status:           models.StatusRevoked,
		RevocationReason: models.RevocationReason(0),
	})
	if err != nil {
		t.Fatalf("could not revoke CA %s: %s", caID, err)
	}

	err = caTest.Service.DeleteCA(context.Background(), services.DeleteCAInput{CAID: caID, CascadeDelete: cascade})
	if err != nil {
		t.Fatalf("could not delete CA %s: %s", caID, err)
	}
	verifyCADeleted(t, caTest, caID, "CA")
}

// assertKeyBindings checks that the key is bound exactly once to each of the given CAs, and to nothing else.
func assertKeyBindings(t *testing.T, keyURI string, cas ...*models.CACertificate) {
	t.Helper()
	key, err := serverTest.KMS.Service.GetKey(context.Background(), services.GetKeyInput{Identifier: keyURI})
	if err != nil {
		t.Fatalf("key %s should exist: %s", keyURI, err)
	}
	bound, err := key.BoundResources()
	if err != nil {
		t.Fatalf("could not read the resources bound to key %s: %s", keyURI, err)
	}

	expected := []models.KMSBindResource{}
	for _, ca := range cas {
		expected = append(expected, models.KMSBindResource{ResourceType: models.KMSBindResourceTypeCertificate, ResourceID: ca.Certificate.SerialNumber})
	}
	assert.ElementsMatch(t, expected, bound)
}

func assertKeyExists(t *testing.T, keyURI string) {
	t.Helper()
	if _, err := serverTest.KMS.Service.GetKey(context.Background(), services.GetKeyInput{Identifier: keyURI}); err != nil {
		t.Fatalf("key %s should exist: %s", keyURI, err)
	}
}

func assertCACanSign(t *testing.T, caTest *tests.CATestServer, ca *models.CACertificate) {
	t.Helper()
	key, err := chelpers.GenerateRSAKey(2048)
	if err != nil {
		t.Fatalf("could not generate key: %s", err)
	}
	csr, err := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "cross-sign-leaf"}, key)
	if err != nil {
		t.Fatalf("could not generate CSR: %s", err)
	}

	_, err = caTest.Service.SignCertificate(context.Background(), services.SignCertificateInput{
		CAID:              ca.ID,
		CertRequest:       (*models.X509CertificateRequest)(csr),
		IssuanceProfileID: ca.ProfileID,
	})
	if err != nil {
		t.Fatalf("CA %s (%s) should be able to sign: %s", ca.ID, ca.Certificate.Subject.CommonName, err)
	}
}
