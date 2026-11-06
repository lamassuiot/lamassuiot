package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	backendservices "github.com/lamassuiot/lamassuiot/v4/backend/pkg/services"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	"testing"
	"time"

	chelpers "github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// F10: exercise the HTTP write responses, including the independently derived GET value.
func TestCertificateWriteResponsesHavePrivateKey(t *testing.T) {
	require.NoError(t, serverTest.BeforeEach())
	ctx := context.Background()
	svc := serverTest.CA.HttpCASDK
	profile := newKeyRefsProfile(t)
	create := func(parent string) *models.CACertificate {
		t.Helper()
		ca, err := svc.CreateCA(ctx, services.CreateCAInput{
			KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.ECDSA), Bits: 256},
			Subject:      models.Subject{CommonName: "F10 write responses"},
			CAExpiration: models.Validity{Type: models.Duration, Duration: models.TimeDuration(24 * time.Hour)},
			ProfileID:    profile.ID, ParentID: parent,
		})
		require.NoError(t, err)
		return ca
	}
	check := func(t *testing.T, cert *models.Certificate, want bool) {
		t.Helper()
		read, err := svc.GetCertificateBySerialNumber(ctx, services.GetCertificatesBySerialNumberInput{SerialNumber: cert.SerialNumber})
		require.NoError(t, err)
		assert.Equal(t, want, read.HasPrivateKey, "GET")
		assert.Equal(t, read.HasPrivateKey, cert.HasPrivateKey, "write response must match GET")
	}
	checkCA := func(t *testing.T, ca *models.CACertificate, want bool) {
		t.Helper()
		check(t, &ca.Certificate, want)
		read, err := svc.GetCAByID(ctx, services.GetCAByIDInput{CAID: ca.ID})
		require.NoError(t, err)
		assert.Equal(t, read.Certificate.HasPrivateKey, ca.Certificate.HasPrivateKey)
	}
	issuer := create("")
	t.Run("CreateCA root", func(t *testing.T) { checkCA(t, issuer, true) })
	t.Run("CreateCA subordinate", func(t *testing.T) { checkCA(t, create(issuer.ID), true) })
	for _, withKey := range []bool{true, false} {
		name := "ImportCA without key"
		if withKey {
			name = "ImportCA with key"
		}
		t.Run(name, func(t *testing.T) {
			cert, key := selfSignedCAWithForeignSKI(t, name)
			input := services.ImportCAInput{CACertificate: (*models.X509Certificate)(cert), ProfileID: profile.ID}
			if withKey {
				input.Key = key
			}
			ca, err := svc.ImportCA(ctx, input)
			require.NoError(t, err)
			checkCA(t, ca, withKey)
		})
	}
	for _, managed := range []bool{true, false} {
		name := "SignCertificate external leaf"
		if managed {
			name = "SignCertificate managed leaf"
		}
		t.Run(name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			if managed {
				importKeyInto(t, key, defaultEngine)
			}
			csr, err := chelpers.GenerateCertificateRequest(models.Subject{CommonName: name}, key)
			require.NoError(t, err)
			cert, err := svc.SignCertificate(ctx, services.SignCertificateInput{CAID: issuer.ID, CertRequest: (*models.X509CertificateRequest)(csr), IssuanceProfileID: profile.ID})
			require.NoError(t, err)
			check(t, cert, managed)
		})
	}
	t.Run("ReissueCA", func(t *testing.T) {
		ca, err := svc.ReissueCA(ctx, services.ReissueCAInput{CAID: issuer.ID})
		require.NoError(t, err)
		checkCA(t, ca, true)
	})
}

// CA signatures are persisted like leaf certificates and can later be registered as CAs.
func TestSignCAResponseIsPersisted(t *testing.T) {
	require.NoError(t, serverTest.BeforeEach())
	ctx := context.Background()
	svc := serverTest.CA.HttpCASDK
	profile := newKeyRefsProfile(t)
	issuer := createKeyRefsCA(t, "F10 transient CA issuer", profile.ID, "")
	for _, managed := range []bool{true, false} {
		name := "external key"
		if managed {
			name = "KMS private key"
		}
		t.Run(name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			if managed {
				importKeyInto(t, key, defaultEngine)
			}
			csr, err := chelpers.GenerateCertificateRequest(models.Subject{CommonName: name}, key)
			require.NoError(t, err)
			// Use a separate value so the stored leaf profile keeps its original semantics.
			profileCopy := *profile
			profileCopy.SignAsCA = true
			cert, err := svc.SignCertificate(ctx, services.SignCertificateInput{
				CAID: issuer.ID, CertRequest: (*models.X509CertificateRequest)(csr), IssuanceProfile: &profileCopy,
			})
			require.NoError(t, err)
			require.True(t, cert.IsCA)
			assert.Equal(t, managed, cert.HasPrivateKey)
			stored, err := svc.GetCertificateBySerialNumber(ctx, services.GetCertificatesBySerialNumberInput{SerialNumber: cert.SerialNumber})
			require.NoError(t, err)
			assert.Equal(t, cert, stored)
			registered, err := svc.ImportCA(ctx, services.ImportCAInput{CACertificate: cert.Certificate, ProfileID: profile.ID})
			require.NoError(t, err)
			assert.Equal(t, cert.SerialNumber, registered.CertificateSerialNumber)
			assert.Equal(t, stored, &registered.Certificate)
			assert.Equal(t, issuer.Level+1, registered.Level)
		})
	}
}

func TestCAWritesPreserveCertificateKeyEngineAndIssuer(t *testing.T) {
	require.NoError(t, serverTest.BeforeEach())
	ctx := context.Background()
	svc := serverTest.CA.HttpCASDK
	profile := newKeyRefsProfile(t)
	issuer := createKeyRefsCA(t, "separated issuer", profile.ID, "")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	importKeyInto(t, key, defaultEngine, otherEngine)
	identifier := "pkcs11:token-id=" + otherEngine + ";id=" + kmsKeyIDOf(t, &key.PublicKey) + ";type=private"
	ca, err := svc.CreateCA(ctx, services.CreateCAInput{
		ParentID: issuer.ID, ProfileID: profile.ID,
		Subject:      models.Subject{CommonName: "separated subordinate"},
		KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.ECDSA), Bits: 256, KeyID: identifier},
		CAExpiration: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour)},
	})
	require.NoError(t, err)
	require.Equal(t, otherEngine, ca.Certificate.EngineID)
	require.Equal(t, issuer.Level+1, ca.Level)

	child, err := svc.CreateCA(ctx, services.CreateCAInput{
		ParentID: ca.ID, ProfileID: profile.ID,
		Subject:      models.Subject{CommonName: "separated grandchild"},
		KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.ECDSA), Bits: 256},
		CAExpiration: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour)},
	})
	require.NoError(t, err)
	require.Equal(t, models.IssuerCAMetadata{ID: ca.ID, SN: ca.Certificate.SerialNumber, Level: ca.Level}, child.Certificate.IssuerCAMetadata)
	read, err := svc.GetCertificateBySerialNumber(ctx, services.GetCertificatesBySerialNumberInput{SerialNumber: child.CertificateSerialNumber})
	require.NoError(t, err)
	require.Equal(t, child.Certificate.IssuerCAMetadata, read.IssuerCAMetadata)

	previous := ca.CertificateSerialNumber
	ca, err = svc.ReissueCA(ctx, services.ReissueCAInput{CAID: ca.ID})
	require.NoError(t, err)
	require.NotEqual(t, previous, ca.CertificateSerialNumber)
	require.Equal(t, otherEngine, ca.Certificate.EngineID)
	require.Equal(t, previous, ca.Certificate.Metadata[models.CAMetadataReissuedFromKey])
	read, err = svc.GetCertificateBySerialNumber(ctx, services.GetCertificatesBySerialNumberInput{SerialNumber: previous})
	require.NoError(t, err)
	require.Equal(t, ca.CertificateSerialNumber, read.Metadata[models.CAMetadataReissuedAsKey])
	require.Equal(t, otherEngine, read.EngineID)
}

// Public-key discovery is best effort; CA creation must keep its already resolved key.
type incompleteKeyDiscovery struct {
	services.KMSService
	lookupErr  error
	onlyEngine string
}

func (kms incompleteKeyDiscovery) GetKeysByPublicKey(ctx context.Context, input services.GetKeysByPublicKeyInput) ([]*models.Key, error) {
	if kms.lookupErr != nil {
		return nil, kms.lookupErr
	}
	keys, err := kms.KMSService.GetKeysByPublicKey(ctx, input)
	if err != nil {
		return nil, err
	}
	var filtered []*models.Key
	for _, key := range keys {
		if key.EngineID == kms.onlyEngine {
			filtered = append(filtered, key)
		}
	}
	return filtered, nil
}

func TestCACreationKeepsResolvedKeyWhenDiscoveryIsIncomplete(t *testing.T) {
	require.NoError(t, serverTest.BeforeEach())
	ctx := context.Background()
	profile := newKeyRefsProfile(t)
	issuer := createKeyRefsCA(t, "resolved key issuer", profile.ID, "")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	importKeyInto(t, key, defaultEngine, otherEngine)
	keyID := kmsKeyIDOf(t, &key.PublicKey)
	logger := chelpers.SetupLogger(config.Info, "Test", "resolved CA key")
	engine, err := storage.GetEngineBuilder(serverTest.Storage.Config.Provider)(logger, serverTest.Storage.Config)
	require.NoError(t, err)
	cas, err := engine.GetCAStorage()
	require.NoError(t, err)
	certs, err := engine.GetCertStorage()
	require.NoError(t, err)
	profiles, err := engine.GetIssuanceProfileStorage()
	require.NoError(t, err)
	for _, tc := range []struct {
		name      string
		lookupErr error
	}{
		{"lookup fails", errors.New("discovery unavailable")},
		{"chosen engine omitted", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, err := backendservices.NewCAService(backendservices.CAServiceBuilder{
				Logger: logger, CAStorage: cas, CertificateStorage: certs, IssuanceProfileStorage: profiles,
				KMSService: incompleteKeyDiscovery{KMSService: serverTest.KMS.Service, lookupErr: tc.lookupErr, onlyEngine: defaultEngine},
			})
			require.NoError(t, err)
			ca, err := svc.CreateCA(ctx, services.CreateCAInput{
				ParentID: issuer.ID, ProfileID: profile.ID,
				Subject:      models.Subject{CommonName: tc.name},
				KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.ECDSA), Bits: 256, KeyID: "pkcs11:token-id=" + otherEngine + ";id=" + keyID + ";type=private"},
				CAExpiration: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour)},
			})
			require.NoError(t, err)
			require.Equal(t, keyID, ca.Certificate.KeyID)
			require.Equal(t, otherEngine, ca.Certificate.EngineID)
			require.True(t, ca.Certificate.HasPrivateKey)
			ca, err = svc.ReissueCA(ctx, services.ReissueCAInput{CAID: ca.ID})
			require.NoError(t, err)
			require.Equal(t, keyID, ca.Certificate.KeyID)
			require.Equal(t, otherEngine, ca.Certificate.EngineID)
			require.True(t, ca.Certificate.HasPrivateKey)
		})
	}
}
