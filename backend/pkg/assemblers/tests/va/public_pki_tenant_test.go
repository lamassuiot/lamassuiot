package va

import (
	"crypto/x509"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/assemblers/tests"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"golang.org/x/crypto/ocsp"
)

const (
	publicPKITenantA = "00000000-0000-0000-0000-00000000000a"
	publicPKITenantB = "00000000-0000-0000-0000-00000000000b"
)

// TestPublicCRLAndOCSPAreTenantScoped checks the public VA endpoints: the
// certificate carries tenant-scoped CRL/OCSP URLs, those URLs serve the
// tenant's CA, and the same CA SKI under another or an unknown tenant is not
// found.
func TestPublicCRLAndOCSPAreTenantScoped(t *testing.T) {
	serverTest, err := StartVAServiceTestServer(t)
	if err != nil {
		t.Fatalf("could not create VA test server: %s", err)
	}
	if err := serverTest.BeforeEach(); err != nil {
		t.Fatalf("could not reset test server: %s", err)
	}
	ctxA := tests.TenantContextFor(publicPKITenantA)
	ctxB := tests.TenantContextFor(publicPKITenantB)

	profile, err := serverTest.CA.Service.CreateIssuanceProfile(ctxA, services.CreateIssuanceProfileInput{
		Profile: models.IssuanceProfile{Validity: models.Validity{Type: models.Duration, Duration: models.TimeDuration(12 * time.Hour)}},
	})
	if err != nil {
		t.Fatalf("could not create profile in tenant A: %s", err)
	}
	ca, err := serverTest.CA.Service.CreateCA(ctxA, services.CreateCAInput{
		ID:           "public-pki-ca-a",
		KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
		Subject:      models.Subject{CommonName: "Tenant A CA"},
		CAExpiration: models.Validity{Type: models.Duration, Duration: models.TimeDuration(24 * time.Hour)},
		ProfileID:    profile.ID,
	})
	if err != nil {
		t.Fatalf("could not create CA in tenant A: %s", err)
	}
	key, err := chelpers.GenerateRSAKey(2048)
	if err != nil {
		t.Fatalf("could not generate key: %s", err)
	}
	csr, err := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "device-a"}, key)
	if err != nil {
		t.Fatalf("could not generate CSR: %s", err)
	}
	crt, err := serverTest.CA.Service.SignCertificate(ctxA, services.SignCertificateInput{
		CAID: ca.ID, CertRequest: (*models.X509CertificateRequest)(csr), IssuanceProfileID: profile.ID,
	})
	if err != nil {
		t.Fatalf("could not sign certificate in tenant A: %s", err)
	}

	issued := (*x509.Certificate)(crt.Certificate)
	wantCRL := fmt.Sprintf("/tenants/%s/crl/", publicPKITenantA)
	wantOCSP := fmt.Sprintf("/tenants/%s/ocsp", publicPKITenantA)
	if len(issued.CRLDistributionPoints) == 0 || !strings.Contains(issued.CRLDistributionPoints[0], wantCRL) {
		t.Fatalf("certificate CRL distribution points %v do not contain %q", issued.CRLDistributionPoints, wantCRL)
	}
	if len(issued.OCSPServer) == 0 || !strings.HasSuffix(issued.OCSPServer[0], wantOCSP) {
		t.Fatalf("certificate OCSP servers %v do not end with %q", issued.OCSPServer, wantOCSP)
	}

	caCert := (*x509.Certificate)(ca.Certificate.Certificate)
	ski := string(ca.Certificate.SubjectKeyID)
	err = tests.SleepRetry(10, 2*time.Second, func() error {
		_, err := serverTest.VA.HttpVASDK.GetCRL(ctxA, services.GetCRLResponseInput{CASubjectKeyID: ski, Issuer: caCert, VerifyResponse: true})
		return err
	})
	if err != nil {
		t.Fatalf("tenant A CRL is not served on its tenant URL: %s", err)
	}

	response, err := serverTest.VA.HttpVASDK.GetOCSPResponsePost(ctxA, services.GetOCSPResponseInput{Certificate: issued, Issuer: caCert, VerifyResponse: true})
	if err != nil {
		t.Fatalf("tenant A OCSP failed on its tenant URL: %s", err)
	}
	if response.Status != ocsp.Good {
		t.Fatalf("expected good OCSP status for tenant A certificate, got %d", response.Status)
	}
	if _, err := serverTest.VA.HttpVASDK.GetOCSPResponsePost(ctxB, services.GetOCSPResponseInput{Certificate: issued, Issuer: caCert, VerifyResponse: true}); err == nil {
		t.Fatal("tenant B OCSP URL must not answer for a tenant A certificate")
	}

	for _, path := range []string{
		fmt.Sprintf("/tenants/%s/crl/%s", publicPKITenantB, ski),
		fmt.Sprintf("/tenants/%s/crl/%s", "00000000-0000-0000-0000-0000000000ff", ski),
	} {
		resp, err := http.Get(serverTest.VA.HttpServerURL + path)
		if err != nil {
			t.Fatalf("GET %s: %s", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("GET %s: expected 404, got %d", path, resp.StatusCode)
		}
	}
}
