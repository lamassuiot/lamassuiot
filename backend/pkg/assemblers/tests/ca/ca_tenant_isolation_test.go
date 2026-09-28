package ca

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/assemblers/tests"
	core "github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"golang.org/x/crypto/ocsp"
)

func caTenantTestContext(tenantID string) context.Context {
	return core.WithTenantContext(context.Background(), core.TenantContext{
		OrganizationID: "org-ca-isolation",
		TenantID:       tenantID,
		ActorID:        "actor-ca-isolation",
		ActorType:      "test",
		CorrelationID:  "correlation-" + tenantID,
		Source:         "test",
		TenantStatus:   core.TenantActive,
		Validated:      true,
	})
}

func TestCAServiceTenantIsolation(t *testing.T) {
	serverTest, err := tests.TestServiceBuilder{}.WithDatabase("ca", "kms").WithTenantIDs(
		"00000000-0000-0000-0000-00000000000a",
		"00000000-0000-0000-0000-00000000000b",
	).Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	service := serverTest.CA.Service
	tenantA := caTenantTestContext("00000000-0000-0000-0000-00000000000a")
	tenantB := caTenantTestContext("00000000-0000-0000-0000-00000000000b")
	suspendedTenant := core.WithTenantContext(context.Background(), core.TenantContext{
		OrganizationID: "org-ca-isolation",
		TenantID:       "00000000-0000-0000-0000-00000000000a",
		ActorID:        "actor-ca-isolation",
		ActorType:      "test",
		CorrelationID:  "correlation-suspended",
		Source:         "test",
		TenantStatus:   core.TenantSuspended,
		Validated:      true,
	})
	if _, err := serverTest.CA.Service.GetCAByID(suspendedTenant, services.GetCAByIDInput{CAID: "missing-context"}); !errors.Is(err, core.ErrTenantContextInvalid) {
		t.Fatalf("expected suspended tenant context to be rejected, got %v", err)
	}

	profile, err := service.CreateIssuanceProfile(tenantA, services.CreateIssuanceProfileInput{
		Profile: models.IssuanceProfile{
			Name:     "tenant-a-profile",
			SignAsCA: true,
			Validity: models.Validity{Type: models.Duration, Duration: models.TimeDuration(24 * time.Hour)},
		},
	})
	if err != nil {
		t.Fatalf("could not create tenant A profile: %s", err)
	}

	ca, err := service.CreateCA(tenantA, services.CreateCAInput{
		KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
		Subject:      models.Subject{CommonName: "same-subject-ca"},
		ProfileID:    profile.ID,
		CAExpiration: models.Validity{Type: models.Duration, Duration: models.TimeDuration(24 * time.Hour)},
	})
	if err != nil {
		t.Fatalf("could not create tenant A CA: %s", err)
	}
	tenantAID := "00000000-0000-0000-0000-00000000000a"
	if ca.TenantID != tenantAID || ca.Certificate.TenantID != tenantAID {
		t.Fatalf("CA and embedded certificate must inherit the validated tenant %s, got CA=%s certificate=%s", tenantAID, ca.TenantID, ca.Certificate.TenantID)
	}
	storedCA, err := service.GetCAByID(tenantA, services.GetCAByIDInput{CAID: ca.ID})
	if err != nil {
		t.Fatalf("could not retrieve tenant A CA after creation: %s", err)
	}
	if storedCA.TenantID != tenantAID || storedCA.Certificate.TenantID != tenantAID {
		t.Fatalf("persisted CA and embedded certificate must belong to tenant %s, got CA=%s certificate=%s", tenantAID, storedCA.TenantID, storedCA.Certificate.TenantID)
	}

	if _, err := service.GetCAByID(tenantB, services.GetCAByIDInput{CAID: ca.ID}); !errors.Is(err, errs.ErrCANotFound) {
		t.Fatalf("expected tenant B CA lookup to be hidden, got %v", err)
	}
	if _, err := service.GetCAByID(tenantB, services.GetCAByIDInput{CAID: "unknown-ca-id"}); !errors.Is(err, errs.ErrCANotFound) {
		t.Fatalf("expected unknown CA lookup to use the same not-found error, got %v", err)
	}
	if _, err := service.GetCertificatesByCA(tenantB, services.GetCertificatesByCAInput{CAID: ca.ID}); !errors.Is(err, errs.ErrCANotFound) {
		t.Fatalf("expected tenant B certificate lookup to be hidden, got %v", err)
	}
	if _, err := service.UpdateCAStatus(tenantB, services.UpdateCAStatusInput{CAID: ca.ID, Status: models.StatusRevoked, RevocationReason: ocsp.CessationOfOperation}); !errors.Is(err, errs.ErrCANotFound) {
		t.Fatalf("expected tenant B CA revocation to be rejected, got %v", err)
	}

	profileB, err := service.CreateIssuanceProfile(tenantB, services.CreateIssuanceProfileInput{
		Profile: models.IssuanceProfile{Name: "tenant-b-certificate-profile"},
	})
	if err != nil {
		t.Fatalf("could not create tenant B certificate profile: %s", err)
	}
	_, err = service.CreateCertificate(tenantA, services.CreateCertificateInput{
		CAID:              ca.ID,
		KeySpec:           services.CertificateKeySpec{Type: models.KeyType(x509.RSA), Bits: 2048},
		Subject:           models.Subject{CommonName: "wrong-profile"},
		IssuanceProfileID: profileB.ID,
	})
	if !errors.Is(err, errs.ErrIssuanceProfileNotFound) {
		t.Fatalf("expected cross-tenant profile to be hidden, got %v", err)
	}

	caB, err := createTenantIsolationCA(service, tenantB, "same-subject-ca")
	if err != nil {
		t.Fatalf("could not create tenant B CA: %s", err)
	}
	if ca.ID == caB.ID || ca.Certificate.Subject.CommonName != caB.Certificate.Subject.CommonName || ca.TenantID == caB.TenantID {
		t.Fatalf("same-subject CAs must remain distinct and tenant-owned: A=%s/%s, B=%s/%s", ca.ID, ca.TenantID, caB.ID, caB.TenantID)
	}

	leafProfileA, err := service.CreateIssuanceProfile(tenantA, services.CreateIssuanceProfileInput{
		Profile: models.IssuanceProfile{Name: "tenant-a-leaf-profile", SignAsCA: false},
	})
	if err != nil {
		t.Fatalf("could not create tenant A leaf profile: %s", err)
	}
	leafProfileB, err := service.CreateIssuanceProfile(tenantB, services.CreateIssuanceProfileInput{
		Profile: models.IssuanceProfile{Name: "tenant-b-leaf-profile", SignAsCA: false},
	})
	if err != nil {
		t.Fatalf("could not create tenant B leaf profile: %s", err)
	}

	type issuedCertificate struct {
		ctx         context.Context
		certificate *models.Certificate
		tenantID    string
		err         error
	}
	issued := make(chan issuedCertificate, 2)
	var group sync.WaitGroup
	for _, input := range []struct {
		ctx       context.Context
		ca        string
		cn        string
		profileID string
		tenantID  string
	}{
		{ctx: tenantA, ca: ca.ID, cn: "tenant-a-leaf", profileID: leafProfileA.ID, tenantID: tenantAID},
		{ctx: tenantB, ca: caB.ID, cn: "tenant-b-leaf", profileID: leafProfileB.ID, tenantID: "00000000-0000-0000-0000-00000000000b"},
	} {
		input := input
		group.Add(1)
		go func() {
			defer group.Done()
			certificate, issueErr := service.CreateCertificate(input.ctx, services.CreateCertificateInput{
				CAID:              input.ca,
				KeySpec:           services.CertificateKeySpec{Type: models.KeyType(x509.RSA), Bits: 2048},
				Subject:           models.Subject{CommonName: input.cn},
				IssuanceProfileID: input.profileID,
			})
			issued <- issuedCertificate{ctx: input.ctx, certificate: certificate, tenantID: input.tenantID, err: issueErr}
		}()
	}
	group.Wait()
	close(issued)

	certificates := make([]issuedCertificate, 0, 2)
	for result := range issued {
		if result.err != nil {
			t.Fatalf("concurrent tenant certificate issuance failed: %s", result.err)
		}
		certificates = append(certificates, result)
	}
	if len(certificates) != 2 {
		t.Fatalf("expected two concurrently issued certificates, got %d", len(certificates))
	}
	for _, result := range certificates {
		if result.certificate.TenantID != result.tenantID {
			t.Fatalf("issued leaf certificate has the wrong tenant: expected %s, got %s", result.tenantID, result.certificate.TenantID)
		}
		if result.certificate.IsCA {
			t.Fatalf("expected a persisted leaf certificate, got CA certificate %s", result.certificate.SerialNumber)
		}
		stored, getErr := service.GetCertificateBySerialNumber(result.ctx, services.GetCertificatesBySerialNumberInput{
			SerialNumber: result.certificate.SerialNumber,
		})
		if getErr != nil {
			t.Fatalf("issued leaf certificate %s was not persisted: %s", result.certificate.SerialNumber, getErr)
		}
		if stored.IsCA || stored.SerialNumber != result.certificate.SerialNumber {
			t.Fatalf("expected persisted leaf certificate %s, got IsCA=%t serial=%s", result.certificate.SerialNumber, stored.IsCA, stored.SerialNumber)
		}
		if stored.TenantID != result.tenantID {
			t.Fatalf("persisted leaf certificate has the wrong tenant: expected %s, got %s", result.tenantID, stored.TenantID)
		}
	}

	type revokedCertificate struct {
		certificate *models.Certificate
		err         error
	}
	revocationResults := make(chan revokedCertificate, len(certificates))
	for _, issuedCertificate := range certificates {
		issuedCertificate := issuedCertificate
		group.Add(1)
		go func() {
			defer group.Done()
			updated, revokeErr := service.UpdateCertificateStatus(issuedCertificate.ctx, services.UpdateCertificateStatusInput{
				SerialNumber:     issuedCertificate.certificate.SerialNumber,
				NewStatus:        models.StatusRevoked,
				RevocationReason: ocsp.CessationOfOperation,
			})
			revocationResults <- revokedCertificate{certificate: updated, err: revokeErr}
		}()
	}
	group.Wait()
	close(revocationResults)
	for result := range revocationResults {
		if result.err != nil {
			t.Fatalf("concurrent tenant certificate revocation failed: %s", result.err)
		}
		if result.certificate.Status != models.StatusRevoked {
			t.Fatalf("expected concurrently revoked certificate, got %s", result.certificate.Status)
		}
	}

	tenantACertificate, err := service.CreateCertificate(tenantA, services.CreateCertificateInput{
		CAID:              ca.ID,
		KeySpec:           services.CertificateKeySpec{Type: models.KeyType(x509.RSA), Bits: 2048},
		Subject:           models.Subject{CommonName: "tenant-a-revocation"},
		IssuanceProfileID: leafProfileA.ID,
	})
	if err != nil {
		t.Fatalf("tenant A sequential certificate issuance failed: %s", err)
	}

	found, err := service.GetCertificateBySerialNumber(tenantA, services.GetCertificatesBySerialNumberInput{
		SerialNumber: tenantACertificate.SerialNumber,
	})
	if err != nil {
		t.Fatalf("tenant A could not retrieve certificate %s by serial: %s", tenantACertificate.SerialNumber, err)
	}
	if found.SerialNumber != tenantACertificate.SerialNumber {
		t.Fatalf("retrieved certificate serial %s differs from issued serial %s", found.SerialNumber, tenantACertificate.SerialNumber)
	}

	if _, err := service.GetCertificateBySerialNumber(tenantB, services.GetCertificatesBySerialNumberInput{
		SerialNumber: tenantACertificate.SerialNumber,
	}); !errors.Is(err, errs.ErrCertificateNotFound) {
		t.Fatalf("expected tenant B certificate lookup to be hidden, got %v", err)
	}

	revoked, err := service.UpdateCertificateStatus(tenantA, services.UpdateCertificateStatusInput{
		SerialNumber:     tenantACertificate.SerialNumber,
		NewStatus:        models.StatusRevoked,
		RevocationReason: ocsp.CessationOfOperation,
	})
	if err != nil {
		t.Fatalf("tenant A could not revoke its certificate: %s", err)
	}
	if revoked.Status != models.StatusRevoked {
		t.Fatalf("expected revoked certificate status, got %s", revoked.Status)
	}
}

func TestCAImportsAndQueriesAreTenantScoped(t *testing.T) {
	serverTest, err := tests.TestServiceBuilder{}.WithDatabase("ca", "kms").WithTenantIDs(
		"00000000-0000-0000-0000-00000000000a",
		"00000000-0000-0000-0000-00000000000b",
	).Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	service := serverTest.CA.Service
	tenantA := caTenantTestContext("00000000-0000-0000-0000-00000000000a")
	tenantB := caTenantTestContext("00000000-0000-0000-0000-00000000000b")

	externalCA, caKey, err := chelpers.GenerateSelfSignedCA(x509.ECDSA, 24*time.Hour, "tenant-a-imported-root")
	if err != nil {
		t.Fatalf("could not generate external CA: %s", err)
	}
	profile, err := service.CreateIssuanceProfile(tenantA, services.CreateIssuanceProfileInput{
		Profile: models.IssuanceProfile{Name: "tenant-a-imported-ca-profile"},
	})
	if err != nil {
		t.Fatalf("could not create tenant A CA profile: %s", err)
	}
	importedCA, err := service.ImportCA(tenantA, services.ImportCAInput{
		ProfileID: profile.ID, CACertificate: (*models.X509Certificate)(externalCA),
	})
	if err != nil {
		t.Fatalf("could not import CA for tenant A: %s", err)
	}
	if importedCA.TenantID != "00000000-0000-0000-0000-00000000000a" {
		t.Fatalf("imported CA has tenant %q, want tenant A", importedCA.TenantID)
	}
	if _, err := service.GetCAByID(tenantB, services.GetCAByIDInput{CAID: importedCA.ID}); !errors.Is(err, errs.ErrCANotFound) {
		t.Fatalf("expected tenant B imported CA lookup to be hidden, got %v", err)
	}

	makeLeaf := func(serial int64, commonName string) *models.X509Certificate {
		key, keyErr := chelpers.GenerateRSAKey(2048)
		if keyErr != nil {
			t.Fatalf("could not generate leaf key: %s", keyErr)
		}
		request, requestErr := chelpers.GenerateCertificateRequest(models.Subject{CommonName: commonName}, key)
		if requestErr != nil {
			t.Fatalf("could not generate leaf request: %s", requestErr)
		}
		template := &x509.Certificate{
			SerialNumber:          big.NewInt(serial),
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
			SubjectKeyId:          fmt.Appendf(nil, "leaf-ski-%d", serial),
			AuthorityKeyId:        externalCA.SubjectKeyId,
		}
		der, certErr := x509.CreateCertificate(rand.Reader, template, externalCA, request.PublicKey, caKey)
		if certErr != nil {
			t.Fatalf("could not sign imported leaf: %s", certErr)
		}
		certificate, certErr := x509.ParseCertificate(der)
		if certErr != nil {
			t.Fatalf("could not parse imported leaf: %s", certErr)
		}
		return (*models.X509Certificate)(certificate)
	}

	certificateA, err := service.ImportCertificate(tenantA, services.ImportCertificateInput{
		Certificate: makeLeaf(101, "tenant-a-imported-leaf"),
	})
	if err != nil {
		t.Fatalf("could not import tenant A certificate: %s", err)
	}
	certificateB, err := service.ImportCertificate(tenantB, services.ImportCertificateInput{
		Certificate: makeLeaf(102, "tenant-b-imported-leaf"),
	})
	if err != nil {
		t.Fatalf("could not import tenant B certificate: %s", err)
	}
	if certificateA.TenantID != "00000000-0000-0000-0000-00000000000a" || certificateA.IssuerCAMetadata.ID != importedCA.ID {
		t.Fatalf("tenant A import must resolve its own CA, got tenant=%q issuer=%q", certificateA.TenantID, certificateA.IssuerCAMetadata.ID)
	}
	if certificateB.TenantID != "00000000-0000-0000-0000-00000000000b" || certificateB.IssuerCAMetadata.ID == importedCA.ID {
		t.Fatalf("tenant B import must not inherit tenant A CA, got tenant=%q issuer=%q", certificateB.TenantID, certificateB.IssuerCAMetadata.ID)
	}
	if _, err := service.GetCertificateBySerialNumber(tenantB, services.GetCertificatesBySerialNumberInput{SerialNumber: certificateA.SerialNumber}); !errors.Is(err, errs.ErrCertificateNotFound) {
		t.Fatalf("expected tenant B imported certificate lookup to be hidden, got %v", err)
	}
	if _, err := createTenantIsolationCA(service, tenantA, "tenant-a-second-ca"); err != nil {
		t.Fatalf("could not create second tenant A CA for pagination: %s", err)
	}

	var tenantACAs []models.CACertificate
	if _, err := service.GetCAs(tenantA, services.GetCAsInput{ExhaustiveRun: true, ApplyFunc: func(ca models.CACertificate) {
		tenantACAs = append(tenantACAs, ca)
	}}); err != nil {
		t.Fatalf("could not list tenant A CAs: %s", err)
	}
	var tenantBCAs []models.CACertificate
	if _, err := service.GetCAsByCommonName(tenantB, services.GetCAsByCommonNameInput{
		CommonName: "tenant-a-imported-root", ExhaustiveRun: true,
		ApplyFunc: func(ca models.CACertificate) { tenantBCAs = append(tenantBCAs, ca) },
	}); err != nil {
		t.Fatalf("could not query tenant B CAs by common name: %s", err)
	}
	if len(tenantACAs) != 2 || tenantACAs[0].TenantID != "00000000-0000-0000-0000-00000000000a" || tenantACAs[1].TenantID != "00000000-0000-0000-0000-00000000000a" || len(tenantBCAs) != 0 {
		t.Fatalf("CA list/filter crossed tenant scope: tenant A=%+v tenant B=%+v", tenantACAs, tenantBCAs)
	}

	var firstPage, secondPage []models.CACertificate
	bookmark, err := service.GetCAs(tenantA, services.GetCAsInput{
		QueryParameters: &resources.QueryParameters{
			PageSize: 1,
			Sort: resources.SortOptions{
				SortMode:  resources.SortModeAsc,
				SortField: "id",
			},
		},
		ApplyFunc: func(ca models.CACertificate) { firstPage = append(firstPage, ca) },
	})
	if err != nil {
		t.Fatalf("could not get first tenant A CA page: %s", err)
	}
	if bookmark == "" || len(firstPage) != 1 {
		t.Fatalf("expected first tenant A page and next bookmark, got page=%+v bookmark=%q", firstPage, bookmark)
	}
	if _, err := service.GetCAs(tenantA, services.GetCAsInput{
		QueryParameters: &resources.QueryParameters{NextBookmark: bookmark},
		ApplyFunc:       func(ca models.CACertificate) { secondPage = append(secondPage, ca) },
	}); err != nil {
		t.Fatalf("could not get second tenant A CA page: %s", err)
	}
	if len(secondPage) != 1 || firstPage[0].TenantID != "00000000-0000-0000-0000-00000000000a" || secondPage[0].TenantID != "00000000-0000-0000-0000-00000000000a" || firstPage[0].ID >= secondPage[0].ID {
		t.Fatalf("CA ordering or pagination crossed tenant scope: first=%+v second=%+v", firstPage, secondPage)
	}

	statsA, err := service.GetStats(tenantA, services.GetStatsInput{})
	if err != nil {
		t.Fatalf("could not get tenant A stats: %s", err)
	}
	statsB, err := service.GetStats(tenantB, services.GetStatsInput{})
	if err != nil {
		t.Fatalf("could not get tenant B stats: %s", err)
	}
	if statsA.CACertificatesStats.TotalCAs != 2 || statsB.CACertificatesStats.TotalCAs != 0 {
		t.Fatalf("CA statistics crossed tenant scope: tenant A=%d tenant B=%d", statsA.CACertificatesStats.TotalCAs, statsB.CACertificatesStats.TotalCAs)
	}
}

func createTenantIsolationCA(service services.CAService, ctx context.Context, commonName string) (*models.CACertificate, error) {
	profile, err := service.CreateIssuanceProfile(ctx, services.CreateIssuanceProfileInput{
		Profile: models.IssuanceProfile{Name: fmt.Sprintf("%s-profile", commonName), SignAsCA: true},
	})
	if err != nil {
		return nil, err
	}
	return service.CreateCA(ctx, services.CreateCAInput{
		KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
		Subject:      models.Subject{CommonName: commonName},
		ProfileID:    profile.ID,
		CAExpiration: models.Validity{Type: models.Duration, Duration: models.TimeDuration(24 * time.Hour)},
	})
}
