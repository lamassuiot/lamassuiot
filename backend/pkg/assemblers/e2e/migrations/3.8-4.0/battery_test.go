package migrations38to40

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/backend/pkg/assemblers/tests"
	bhelpers "github.com/lamassuiot/lamassuiot/v4/backend/pkg/helpers"
	chelpers "github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/stretchr/testify/require"
)

// issuanceBattery makes a root sign two levels of subordinate CAs and a leaf, then revokes them from the bottom up:
// each revocation must reach the CRL of its issuer, signed by the issuer's key. The last one is signed by the root,
// whose key, for A, B and C, went through the upgrade.
func (e *env) issuanceBattery(t *testing.T, srv *tests.TestServer, name string, profile *models.IssuanceProfile) {
	ctx := context.Background()
	caSvc := srv.CA.Service
	rootCA, err := caSvc.GetCAByID(ctx, services.GetCAByIDInput{CAID: e.caID[name]})
	require.NoError(t, err)
	root := (*x509.Certificate)(rootCA.Certificate.Certificate)

	createSub := func(parentID, cn string, validity time.Duration) (*models.CACertificate, *x509.Certificate) {
		t.Helper()
		ca, err := caSvc.CreateCA(ctx, services.CreateCAInput{
			ParentID:     parentID,
			KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.ECDSA), Bits: 256},
			Subject:      models.Subject{CommonName: cn},
			CAExpiration: models.Validity{Type: models.Duration, Duration: models.TimeDuration(validity)},
			ProfileID:    profile.ID,
			EngineID:     engineID,
		})
		require.NoError(t, err, "create %s", cn)
		initCRL(t, srv, ca.ID)
		return ca, (*x509.Certificate)(ca.Certificate.Certificate)
	}
	l1, l1Cert := createSub(rootCA.ID, "Upgrade "+name+" L1", 24*time.Hour)
	l2, l2Cert := createSub(l1.ID, "Upgrade "+name+" L2", 12*time.Hour)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	csr, err := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "Upgrade " + name + " leaf"}, leafKey)
	require.NoError(t, err)
	leaf, err := caSvc.SignCertificate(ctx, services.SignCertificateInput{
		CAID: l2.ID, CertRequest: (*models.X509CertificateRequest)(csr), IssuanceProfileID: profile.ID,
	})
	require.NoError(t, err)
	leafCert := (*x509.Certificate)(leaf.Certificate)

	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root)
	intermediates.AddCert(l1Cert)
	intermediates.AddCert(l2Cert)
	_, err = leafCert.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	require.NoError(t, err, "the leaf chains to root %s", name)
	require.Equal(t, root.SubjectKeyId, l1Cert.AuthorityKeyId, "L1 names its issuer by the SKI root %s carries", name)
	require.Equal(t, l1Cert.SubjectKeyId, l2Cert.AuthorityKeyId)

	_, err = caSvc.UpdateCertificateStatus(ctx, services.UpdateCertificateStatusInput{
		SerialNumber: leaf.SerialNumber, NewStatus: models.StatusRevoked, RevocationReason: models.RevocationReason(1),
	})
	require.NoError(t, err)
	requireCRLLists(t, srv, l2.ID, l2Cert, leaf.SerialNumber)
	requireCRLAtCDP(t, srv, leafCert, l2.ID, l2Cert, leaf.SerialNumber)

	revokeCA := func(ca *models.CACertificate) {
		t.Helper()
		_, err := caSvc.UpdateCAStatus(ctx, services.UpdateCAStatusInput{CAID: ca.ID, Status: models.StatusRevoked, RevocationReason: models.RevocationReason(1)})
		require.NoError(t, err)
	}
	revokeCA(l2)
	requireCRLLists(t, srv, l1.ID, l1Cert, l2.Certificate.SerialNumber)
	requireCRLAtCDP(t, srv, l2Cert, l1.ID, l1Cert, l2.Certificate.SerialNumber)
	revokeCA(l1)
	requireCRLLists(t, srv, rootCA.ID, root, l1.Certificate.SerialNumber)
	requireCRLAtCDP(t, srv, l1Cert, rootCA.ID, root, l1.Certificate.SerialNumber)

	if name == "A" || name == "B" || name == "C" {
		// The CDP of what a 3.8 CA issued is /crl/<its SKI>: it serves the same CRL as /crl/<CA id>.
		bySKI := downloadCRL(t, srv, e.fx[name].SKI, root)
		byID := downloadCRL(t, srv, rootCA.ID, root)
		require.Equal(t, byID.Raw, bySKI.Raw, "CRL of %s at /crl/<SKI> and /crl/<CA id>", name)
		require.Contains(t, revokedSerials(bySKI), l1.Certificate.SerialNumber)
	} else {
		// A CA that did not come from 3.8 has no URL by SKI, even when its SKI is its digest (F).
		_, err := srv.VA.HttpVASDK.GetCRL(ctx, services.GetCRLResponseInput{ID: hex.EncodeToString(root.SubjectKeyId), Issuer: root, VerifyResponse: true})
		require.ErrorContains(t, err, "404", "CRL of %s by SKI", name)
	}
}

// requireCRLLists issues the CRL of a CA and checks that the CA's key signed it and that it lists the serial.
func requireCRLLists(t *testing.T, srv *tests.TestServer, caID string, issuer *x509.Certificate, serial string) {
	t.Helper()
	crl, err := srv.VA.CRLService.CalculateCRL(context.Background(), services.CalculateCRLInput{CAID: caID})
	require.NoError(t, err)
	require.NoError(t, crl.CheckSignatureFrom(issuer), "CRL of %s signed by its key", issuer.Subject.CommonName)
	require.Contains(t, revokedSerials(crl), serial, "CRL of %s", issuer.Subject.CommonName)
}

// revokedSerials is copied from backend/pkg/assemblers/tests/va/crl_settings_by_ca_id_test.go.
func revokedSerials(crl *x509.RevocationList) []string {
	var out []string
	for _, e := range crl.RevokedCertificateEntries {
		out = append(out, bhelpers.SerialNumberToHexString(e.SerialNumber))
	}
	return out
}
