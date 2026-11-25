package services

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	coreservices "github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// unknownCertCA knows no certificate, as happens with a bootstrap certificate issued outside Lamassu.
type unknownCertCA struct{ coreservices.CAService }

func (unknownCertCA) GetCertificateBySerialNumber(context.Context, coreservices.GetCertificatesBySerialNumberInput) (*models.Certificate, error) {
	return nil, errs.ErrCertificateNotFound
}

// TestCheckCertificateRevocationWithExternalCRL checks a certificate that Lamassu does not know, with no OCSP
// server and a CRL distribution point published by its (external) issuer.
func TestCheckCertificateRevocationWithExternalCRL(t *testing.T) {
	const clientSerial = 0x1234abcd

	tests := []struct {
		name          string
		revokedSerial int64
		expiredCRL    bool
		wantChecked   bool
		wantRevoked   bool
	}{
		{name: "client serial listed in the CRL", revokedSerial: clientSerial, wantChecked: true, wantRevoked: true},
		{name: "other serial listed in the CRL", revokedSerial: 0x5678, wantChecked: true, wantRevoked: false},
		// An expired CRL may predate the revocation (e.g. an old CRL replayed on the network), so it cannot prove
		// that the certificate is not revoked.
		{name: "other serial listed in an expired CRL", revokedSerial: 0x5678, expiredCRL: true, wantChecked: false},
		// A revocation listed in an expired CRL still happened.
		{name: "client serial listed in an expired CRL", revokedSerial: clientSerial, expiredCRL: true, wantChecked: true, wantRevoked: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			caTemplate := &x509.Certificate{
				SerialNumber:          big.NewInt(1),
				Subject:               pkix.Name{CommonName: "external-bootstrap-ca"},
				NotBefore:             time.Now().Add(-time.Minute),
				NotAfter:              time.Now().Add(time.Hour),
				IsCA:                  true,
				BasicConstraintsValid: true,
				KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			}
			caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
			require.NoError(t, err)
			ca, err := x509.ParseCertificate(caDER)
			require.NoError(t, err)

			thisUpdate, nextUpdate := time.Now().Add(-time.Minute), time.Now().Add(time.Hour)
			if tc.expiredCRL {
				thisUpdate, nextUpdate = time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour)
			}
			crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
				Number:     big.NewInt(1),
				ThisUpdate: thisUpdate,
				NextUpdate: nextUpdate,
				RevokedCertificateEntries: []x509.RevocationListEntry{
					{SerialNumber: big.NewInt(tc.revokedSerial), RevocationTime: time.Now().Add(-time.Minute)},
				},
			}, ca, caKey)
			require.NoError(t, err)

			crlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write(crlDER)
			}))
			defer crlServer.Close()

			clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			clientDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
				SerialNumber:          big.NewInt(clientSerial),
				Subject:               pkix.Name{CommonName: "bootstrap-device"},
				NotBefore:             time.Now().Add(-time.Minute),
				NotAfter:              time.Now().Add(time.Hour),
				CRLDistributionPoints: []string{crlServer.URL},
			}, ca, &clientKey.PublicKey, caKey)
			require.NoError(t, err)
			clientCert, err := x509.ParseCertificate(clientDER)
			require.NoError(t, err)

			logger := logrus.New()
			logger.SetOutput(io.Discard)
			svc := &DMSManagerServiceBackend{caClient: unknownCertCA{}, logger: logrus.NewEntry(logger)}

			checked, revoked, err := svc.checkCertificateRevocation(context.Background(), clientCert, ca)
			require.NoError(t, err)
			require.Equal(t, tc.wantChecked, checked)
			if tc.wantChecked {
				require.Equal(t, tc.wantRevoked, revoked)
			}
		})
	}
}
