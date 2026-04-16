package ca

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/assemblers/tests"
	backendservices "github.com/lamassuiot/lamassuiot/backend/v3/pkg/services"
	coreconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	coreservices "github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	postgresstorage "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3"
	postgresconfig "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3/config"
)

func buildCATestServerWithStorage(t *testing.T) (*tests.TestServer, *tests.TestStorageEngineConfig) {
	t.Helper()

	storageConfig, err := tests.PreparePostgresForTest([]string{"ca", "kms"})
	if err != nil {
		t.Fatalf("could not prepare Postgres test server: %s", err)
	}

	cryptoConfig := tests.PrepareCryptoEnginesForTest([]tests.CryptoEngine{tests.GOLANG})
	eventBusConfig := &tests.TestEventBusConfig{
		Config: coreconfig.EventBusEngine{
			Enabled: false,
		},
	}

	serverTest, err := tests.AssembleServices(storageConfig, eventBusConfig, cryptoConfig, nil, []tests.Service{tests.CA}, false, false)
	if err != nil {
		t.Fatalf("could not assemble test services: %s", err)
	}

	t.Cleanup(serverTest.AfterSuite)

	return serverTest, storageConfig
}

func setStoredKeyHasPrivateKey(t *testing.T, storageConfig *tests.TestStorageEngineConfig, keyID string, hasPrivateKey bool) {
	t.Helper()

	cfg, err := coreconfig.DecodeStruct[postgresconfig.PostgresPSEConfig](storageConfig.Config.Config)
	if err != nil {
		t.Fatalf("could not decode Postgres config: %s", err)
	}

	logger := chelpers.SetupLogger(coreconfig.None, "test", "postgres")
	db, err := postgresstorage.CreatePostgresDBConnection(logger, cfg, postgresstorage.KMS_DB_NAME)
	if err != nil {
		t.Fatalf("could not create Postgres DB connection: %s", err)
	}
	defer func() {
		sqlDB, sqlErr := db.DB()
		if sqlErr == nil {
			sqlDB.Close()
		}
	}()

	repo, err := postgresstorage.NewKMSPostgresRepository(logger, db)
	if err != nil {
		t.Fatalf("could not create KMS repo: %s", err)
	}

	exists, key, err := repo.SelectExistsByKeyID(context.Background(), keyID)
	if err != nil {
		t.Fatalf("could not read KMS key %s: %s", keyID, err)
	}
	if !exists {
		t.Fatalf("expected KMS key %s to exist", keyID)
	}

	key.HasPrivateKey = hasPrivateKey
	if _, err := repo.Update(context.Background(), key); err != nil {
		t.Fatalf("could not update KMS key %s: %s", keyID, err)
	}
}

func createExternallySignedCertificate(t *testing.T, publicKey crypto.PublicKey, issuer *x509.Certificate, issuerKey crypto.Signer, commonName string) *x509.Certificate {
	t.Helper()

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("could not generate serial number: %s", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:   time.Now().Add(-time.Minute),
		NotAfter:    time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, issuer, publicKey, issuerKey)
	if err != nil {
		t.Fatalf("could not create certificate %s: %s", commonName, err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("could not parse certificate %s: %s", commonName, err)
	}

	return cert
}

func createKMSSelfSignedCA(t *testing.T, key *models.Key, kmsSDK coreservices.KMSService, commonName string) *x509.Certificate {
	t.Helper()

	signer := backendservices.NewKMSCryptoSigner(context.Background(), *key, kmsSDK)
	skid, err := hex.DecodeString(key.KeyID)
	if err != nil {
		t.Fatalf("could not decode key ID %s: %s", key.KeyID, err)
	}
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("could not generate serial number: %s", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		SubjectKeyId:          skid,
		AuthorityKeyId:        skid,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		t.Fatalf("could not create self-signed CA %s: %s", commonName, err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("could not parse self-signed CA %s: %s", commonName, err)
	}

	return cert
}

func TestCertificateHasPrivateKeyCreateCertificate(t *testing.T) {
	serverTest, storageConfig := buildCATestServerWithStorage(t)

	t.Run("GeneratedManagedCertificate", func(t *testing.T) {
		if err := serverTest.BeforeEach(); err != nil {
			t.Fatalf("failed running BeforeEach: %s", err)
		}

		ca := createActiveCA(t, serverTest.CA.HttpCASDK)
		cert, err := serverTest.CA.HttpCASDK.CreateCertificate(context.Background(), coreservices.CreateCertificateInput{
			CAID: ca.ID,
			KeySpec: coreservices.CertificateKeySpec{
				Type: models.KeyType(x509.RSA),
				Bits: 2048,
			},
			Subject: models.Subject{CommonName: "generated-managed-cert"},
		})
		if err != nil {
			t.Fatalf("CreateCertificate returned error: %s", err)
		}

		if !cert.HasPrivateKey {
			t.Fatalf("expected generated certificate to have private key")
		}
		if cert.Type != models.CertificateTypeManaged {
			t.Fatalf("expected managed certificate type, got %s", cert.Type)
		}
		if cert.EngineID == "" {
			t.Fatal("expected managed certificate to include engine_id")
		}
		if cert.VersionSchema != "1.1" {
			t.Fatalf("expected version_schema 1.1, got %s", cert.VersionSchema)
		}
	})

	t.Run("ReusedPublicOnlyKMSKey", func(t *testing.T) {
		if err := serverTest.BeforeEach(); err != nil {
			t.Fatalf("failed running BeforeEach: %s", err)
		}

		ca := createActiveCA(t, serverTest.CA.HttpCASDK)
		key, err := serverTest.KMS.HttpKMSSDK.CreateKey(context.Background(), coreservices.CreateKeyInput{
			Algorithm: "RSA",
			Size:      2048,
			Name:      "public-only-cert-key",
		})
		if err != nil {
			t.Fatalf("CreateKey returned error: %s", err)
		}

		setStoredKeyHasPrivateKey(t, storageConfig, key.KeyID, false)

		cert, err := serverTest.CA.HttpCASDK.CreateCertificate(context.Background(), coreservices.CreateCertificateInput{
			CAID: ca.ID,
			KeySpec: coreservices.CertificateKeySpec{
				KeyIdentifier: key.KeyID,
			},
			Subject: models.Subject{CommonName: "public-only-subject-key-cert"},
		})
		if err != nil {
			t.Fatalf("CreateCertificate returned error: %s", err)
		}

		if cert.HasPrivateKey {
			t.Fatal("expected certificate to report no private key")
		}
		if cert.Type != models.CertificateTypeImportedWithoutKey {
			t.Fatalf("expected imported-without-key certificate type, got %s", cert.Type)
		}
		if cert.EngineID != "" {
			t.Fatalf("expected empty engine_id for public-only certificate, got %s", cert.EngineID)
		}
		if cert.VersionSchema != "1.1" {
			t.Fatalf("expected version_schema 1.1, got %s", cert.VersionSchema)
		}
	})
}

func TestCertificateHasPrivateKeyImportCertificate(t *testing.T) {
	serverTest, _ := buildCATestServerWithStorage(t)

	t.Run("MatchingPrivateKeyInKMS", func(t *testing.T) {
		if err := serverTest.BeforeEach(); err != nil {
			t.Fatalf("failed running BeforeEach: %s", err)
		}

		externalCA, externalCAKey, err := chelpers.GenerateSelfSignedCA(x509.RSA, time.Hour, "external-ca")
		if err != nil {
			t.Fatalf("could not generate external CA: %s", err)
		}

		issuerKey, ok := externalCAKey.(*rsa.PrivateKey)
		if !ok {
			t.Fatalf("expected RSA private key, got %T", externalCAKey)
		}

		key, err := serverTest.KMS.HttpKMSSDK.CreateKey(context.Background(), coreservices.CreateKeyInput{
			Algorithm: "RSA",
			Size:      2048,
			Name:      "imported-leaf-managed-key",
		})
		if err != nil {
			t.Fatalf("CreateKey returned error: %s", err)
		}

		leafCert := createExternallySignedCertificate(t, backendservices.NewKMSCryptoSigner(context.Background(), *key, serverTest.KMS.HttpKMSSDK).Public(), externalCA, issuerKey, "imported-leaf-managed")

		importedCert, err := serverTest.CA.HttpCASDK.ImportCertificate(context.Background(), coreservices.ImportCertificateInput{
			Certificate: (*models.X509Certificate)(leafCert),
		})
		if err != nil {
			t.Fatalf("ImportCertificate returned error: %s", err)
		}

		if !importedCert.HasPrivateKey {
			t.Fatal("expected imported certificate to report a private key")
		}
		if importedCert.Type != models.CertificateTypeManaged {
			t.Fatalf("expected managed certificate type, got %s", importedCert.Type)
		}
		if importedCert.EngineID != key.EngineID {
			t.Fatalf("expected engine_id %s, got %s", key.EngineID, importedCert.EngineID)
		}
		if importedCert.VersionSchema != "unknown" {
			t.Fatalf("expected imported certificate version_schema to remain unknown, got %s", importedCert.VersionSchema)
		}
	})

	t.Run("NoMatchingKMSKey", func(t *testing.T) {
		if err := serverTest.BeforeEach(); err != nil {
			t.Fatalf("failed running BeforeEach: %s", err)
		}

		externalCA, externalCAKey, err := chelpers.GenerateSelfSignedCA(x509.RSA, time.Hour, "external-ca")
		if err != nil {
			t.Fatalf("could not generate external CA: %s", err)
		}

		issuerKey, ok := externalCAKey.(*rsa.PrivateKey)
		if !ok {
			t.Fatalf("expected RSA private key, got %T", externalCAKey)
		}

		subjectKey, err := chelpers.GenerateRSAKey(2048)
		if err != nil {
			t.Fatalf("could not generate subject key: %s", err)
		}

		leafCert := createExternallySignedCertificate(t, &subjectKey.PublicKey, externalCA, issuerKey, "imported-leaf-without-kms-key")

		importedCert, err := serverTest.CA.HttpCASDK.ImportCertificate(context.Background(), coreservices.ImportCertificateInput{
			Certificate: (*models.X509Certificate)(leafCert),
		})
		if err != nil {
			t.Fatalf("ImportCertificate returned error: %s", err)
		}

		if importedCert.HasPrivateKey {
			t.Fatal("expected imported certificate to report no private key")
		}
		if importedCert.Type != models.CertificateTypeImportedWithoutKey {
			t.Fatalf("expected imported-without-key certificate type, got %s", importedCert.Type)
		}
		if importedCert.EngineID != "" {
			t.Fatalf("expected empty engine_id, got %s", importedCert.EngineID)
		}
		if importedCert.VersionSchema != "unknown" {
			t.Fatalf("expected imported certificate version_schema to remain unknown, got %s", importedCert.VersionSchema)
		}
	})
}

func TestCertificateHasPrivateKeyImportCA(t *testing.T) {
	serverTest, storageConfig := buildCATestServerWithStorage(t)

	t.Run("MatchingPrivateKeyInKMS", func(t *testing.T) {
		if err := serverTest.BeforeEach(); err != nil {
			t.Fatalf("failed running BeforeEach: %s", err)
		}

		key, err := serverTest.KMS.HttpKMSSDK.CreateKey(context.Background(), coreservices.CreateKeyInput{
			Algorithm: "RSA",
			Size:      2048,
			Name:      "imported-ca-managed-key",
		})
		if err != nil {
			t.Fatalf("CreateKey returned error: %s", err)
		}

		caCert := createKMSSelfSignedCA(t, key, serverTest.KMS.HttpKMSSDK, "imported-ca-managed")
		importedCA, err := serverTest.CA.HttpCASDK.ImportCA(context.Background(), coreservices.ImportCAInput{
			ID:            "managed-import-ca",
			CACertificate: (*models.X509Certificate)(caCert),
		})
		if err != nil {
			t.Fatalf("ImportCA returned error: %s", err)
		}

		if !importedCA.Certificate.HasPrivateKey {
			t.Fatal("expected imported CA certificate to report a private key")
		}
		if importedCA.Certificate.Type != models.CertificateTypeManaged {
			t.Fatalf("expected managed CA certificate type, got %s", importedCA.Certificate.Type)
		}
		if importedCA.Certificate.EngineID != key.EngineID {
			t.Fatalf("expected engine_id %s, got %s", key.EngineID, importedCA.Certificate.EngineID)
		}
	})

	t.Run("PublicOnlyKMSKey", func(t *testing.T) {
		if err := serverTest.BeforeEach(); err != nil {
			t.Fatalf("failed running BeforeEach: %s", err)
		}

		key, err := serverTest.KMS.HttpKMSSDK.CreateKey(context.Background(), coreservices.CreateKeyInput{
			Algorithm: "RSA",
			Size:      2048,
			Name:      "imported-ca-public-only-key",
		})
		if err != nil {
			t.Fatalf("CreateKey returned error: %s", err)
		}

		caCert := createKMSSelfSignedCA(t, key, serverTest.KMS.HttpKMSSDK, "imported-ca-public-only")
		setStoredKeyHasPrivateKey(t, storageConfig, key.KeyID, false)

		importedCA, err := serverTest.CA.HttpCASDK.ImportCA(context.Background(), coreservices.ImportCAInput{
			ID:            fmt.Sprintf("public-only-import-ca-%s", key.KeyID[:8]),
			CACertificate: (*models.X509Certificate)(caCert),
		})
		if err != nil {
			t.Fatalf("ImportCA returned error: %s", err)
		}

		if importedCA.Certificate.HasPrivateKey {
			t.Fatal("expected imported CA certificate to report no private key")
		}
		if importedCA.Certificate.Type != models.CertificateTypeImportedWithoutKey {
			t.Fatalf("expected imported-without-key CA certificate type, got %s", importedCA.Certificate.Type)
		}
		if importedCA.Certificate.EngineID != "" {
			t.Fatalf("expected empty engine_id, got %s", importedCA.Certificate.EngineID)
		}
	})
}

func TestCertificateHasPrivateKeyFiltering(t *testing.T) {
	serverTest, storageConfig := buildCATestServerWithStorage(t)

	t.Run("Certificates", func(t *testing.T) {
		if err := serverTest.BeforeEach(); err != nil {
			t.Fatalf("failed running BeforeEach: %s", err)
		}

		ca := createActiveCA(t, serverTest.CA.HttpCASDK)

		managedCert, err := serverTest.CA.HttpCASDK.CreateCertificate(context.Background(), coreservices.CreateCertificateInput{
			CAID: ca.ID,
			KeySpec: coreservices.CertificateKeySpec{
				Type: models.KeyType(x509.RSA),
				Bits: 2048,
			},
			Subject: models.Subject{CommonName: "filter-managed-cert"},
		})
		if err != nil {
			t.Fatalf("CreateCertificate returned error: %s", err)
		}

		key, err := serverTest.KMS.HttpKMSSDK.CreateKey(context.Background(), coreservices.CreateKeyInput{
			Algorithm: "RSA",
			Size:      2048,
			Name:      "filter-public-only-cert-key",
		})
		if err != nil {
			t.Fatalf("CreateKey returned error: %s", err)
		}
		setStoredKeyHasPrivateKey(t, storageConfig, key.KeyID, false)

		publicOnlyCert, err := serverTest.CA.HttpCASDK.CreateCertificate(context.Background(), coreservices.CreateCertificateInput{
			CAID: ca.ID,
			KeySpec: coreservices.CertificateKeySpec{
				KeyIdentifier: key.KeyID,
			},
			Subject: models.Subject{CommonName: "filter-public-only-cert"},
		})
		if err != nil {
			t.Fatalf("CreateCertificate returned error: %s", err)
		}

		if !managedCert.HasPrivateKey {
			t.Fatal("expected managed certificate to keep private key for filter setup")
		}
		if publicOnlyCert.HasPrivateKey {
			t.Fatal("expected public-only certificate to have no private key for filter setup")
		}

		var found []models.Certificate
		_, err = serverTest.CA.HttpCASDK.GetCertificates(context.Background(), coreservices.GetCertificatesInput{
			ListInput: resources.ListInput[models.Certificate]{
				QueryParameters: &resources.QueryParameters{
					PageSize: 25,
					Filters: []resources.FilterOption{
						{
							Field:           "has_private_key",
							Value:           "false",
							FilterOperation: resources.EnumEqual,
						},
					},
				},
				ExhaustiveRun: true,
				ApplyFunc: func(elem models.Certificate) {
					found = append(found, elem)
				},
			},
		})
		if err != nil {
			t.Fatalf("GetCertificates returned error: %s", err)
		}

		if len(found) != 1 {
			t.Fatalf("expected 1 certificate with has_private_key=false, got %d", len(found))
		}
		if found[0].SerialNumber != publicOnlyCert.SerialNumber {
			t.Fatalf("expected certificate serial %s, got %s", publicOnlyCert.SerialNumber, found[0].SerialNumber)
		}
		if found[0].HasPrivateKey {
			t.Fatal("expected filtered certificate to report no private key")
		}
	})

	t.Run("CAs", func(t *testing.T) {
		if err := serverTest.BeforeEach(); err != nil {
			t.Fatalf("failed running BeforeEach: %s", err)
		}

		managedKey, err := serverTest.KMS.HttpKMSSDK.CreateKey(context.Background(), coreservices.CreateKeyInput{
			Algorithm: "RSA",
			Size:      2048,
			Name:      "filter-managed-ca-key",
		})
		if err != nil {
			t.Fatalf("CreateKey returned error: %s", err)
		}

		managedCACert := createKMSSelfSignedCA(t, managedKey, serverTest.KMS.HttpKMSSDK, "filter-managed-ca")
		managedCA, err := serverTest.CA.HttpCASDK.ImportCA(context.Background(), coreservices.ImportCAInput{
			ID:            "filter-managed-ca",
			CACertificate: (*models.X509Certificate)(managedCACert),
		})
		if err != nil {
			t.Fatalf("ImportCA returned error: %s", err)
		}

		publicOnlyKey, err := serverTest.KMS.HttpKMSSDK.CreateKey(context.Background(), coreservices.CreateKeyInput{
			Algorithm: "RSA",
			Size:      2048,
			Name:      "filter-public-only-ca-key",
		})
		if err != nil {
			t.Fatalf("CreateKey returned error: %s", err)
		}

		publicOnlyCACert := createKMSSelfSignedCA(t, publicOnlyKey, serverTest.KMS.HttpKMSSDK, "filter-public-only-ca")
		setStoredKeyHasPrivateKey(t, storageConfig, publicOnlyKey.KeyID, false)

		publicOnlyCA, err := serverTest.CA.HttpCASDK.ImportCA(context.Background(), coreservices.ImportCAInput{
			ID:            fmt.Sprintf("filter-public-only-ca-%s", publicOnlyKey.KeyID[:8]),
			CACertificate: (*models.X509Certificate)(publicOnlyCACert),
		})
		if err != nil {
			t.Fatalf("ImportCA returned error: %s", err)
		}

		if !managedCA.Certificate.HasPrivateKey {
			t.Fatal("expected managed CA to keep private key for filter setup")
		}
		if publicOnlyCA.Certificate.HasPrivateKey {
			t.Fatal("expected public-only CA to have no private key for filter setup")
		}

		var found []models.CACertificate
		_, err = serverTest.CA.HttpCASDK.GetCAs(context.Background(), coreservices.GetCAsInput{
			QueryParameters: &resources.QueryParameters{
				PageSize: 25,
				Filters: []resources.FilterOption{
					{
						Field:           "has_private_key",
						Value:           "false",
						FilterOperation: resources.EnumEqual,
					},
				},
			},
			ExhaustiveRun: true,
			ApplyFunc: func(elem models.CACertificate) {
				found = append(found, elem)
			},
		})
		if err != nil {
			t.Fatalf("GetCAs returned error: %s", err)
		}

		if len(found) != 1 {
			t.Fatalf("expected 1 CA with has_private_key=false, got %d", len(found))
		}
		if found[0].ID != publicOnlyCA.ID {
			t.Fatalf("expected CA id %s, got %s", publicOnlyCA.ID, found[0].ID)
		}
		if found[0].Certificate.HasPrivateKey {
			t.Fatal("expected filtered CA to report no private key")
		}
	})
}
