package va

import (
	"context"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	chelpers "github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/stretchr/testify/require"
)

// A CA certificate and its key generated with OpenSSL without the cRLSign key usage, which OpenSSL only adds
// when it is asked to:
//
//	openssl ecparam -genkey -name prime256v1 -noout | openssl pkcs8 -topk8 -nocrypt -out ca.key
//	openssl req -x509 -new -key ca.key -subj "/CN=OpenSSL No cRLSign CA" -days 36500 \
//	  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" \
//	  -addext "subjectKeyIdentifier=hash" -out ca.pem
const (
	opensslNoCRLSignCertPEM = `-----BEGIN CERTIFICATE-----
MIIBhTCCASygAwIBAgIUHvUv0pyAgyRaDUMGdWRUcrF7KXUwCgYIKoZIzj0EAwIw
IDEeMBwGA1UEAwwVT3BlblNTTCBObyBjUkxTaWduIENBMCAXDTI2MTEyNDA5MjQ0
NloYDzIxMjYxMDMxMDkyNDQ2WjAgMR4wHAYDVQQDDBVPcGVuU1NMIE5vIGNSTFNp
Z24gQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAThQlf+XVvmaoGXbBNxxxh/
iNYs6hqvEJiBJKD9RN47fYGLC0+jkVkvDzcP47h823oLaVPYQ19CDOSRVtt8KcpY
o0IwQDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwICBDAdBgNVHQ4EFgQU
uCuujRynQxAbY3M7eYD2YOGNLJcwCgYIKoZIzj0EAwIDRwAwRAIgUYD1VbtS1VmP
YnBvqUu/CkgI1mIdVjLVgNM16Th8oVcCIGI2Se+ucvvAWqmOWO9M48+Cw2Nw/fWS
0I22IdXnzFIE
-----END CERTIFICATE-----
`
	opensslNoCRLSignKeyPEM = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgr5acc92ZCvMEOe9D
jmKvLZQL0Qx4GsEHN/yIq6p4hh2hRANCAAThQlf+XVvmaoGXbBNxxxh/iNYs6hqv
EJiBJKD9RN47fYGLC0+jkVkvDzcP47h823oLaVPYQ19CDOSRVtt8KcpY
-----END PRIVATE KEY-----
`
)

// An OpenSSL CA certificate imported with its private key, but without the cRLSign key usage. Its key reaches the
// KMS like any other import, so nothing stops the CA from being created, but it cannot sign a CRL of its own: the
// VA creates no CRL settings for it, and asking it for a CRL fails instead of serving one that does not exist.
func TestOpenSSLCAWithoutCRLSignGetsNoCRLSettings(t *testing.T) {
	require.NoError(t, serverTest.BeforeEach())
	ctx := context.Background()

	caCert, err := chelpers.ParseCertificate(opensslNoCRLSignCertPEM)
	require.NoError(t, err)
	caKey, err := chelpers.ParsePrivateKey([]byte(opensslNoCRLSignKeyPEM))
	require.NoError(t, err)
	require.NotZero(t, caCert.KeyUsage&x509.KeyUsageCertSign, "fixture precondition: OpenSSL issued it with keyCertSign")
	require.Zero(t, caCert.KeyUsage&x509.KeyUsageCRLSign, "fixture precondition: OpenSSL issued it without cRLSign")

	ca, err := serverTest.CA.Service.ImportCA(ctx, services.ImportCAInput{
		ProfileID:     issuanceProfileForImport(t),
		Key:           caKey,
		CACertificate: (*models.X509Certificate)(caCert),
	})
	require.NoError(t, err)
	require.Equal(t, models.CertificateTypeImportedWithKey, ca.Certificate.Type)
	require.NotEmpty(t, ca.Certificate.KeyID, "the CA has its key in the KMS")

	// Long enough for the VA to have handled the ca.import event: finding no settings here means none are created.
	time.Sleep(15 * time.Second)
	_, err = serverTest.VA.CRLService.GetCRLSettings(ctx, services.GetCRLSettingsInput{CAID: ca.ID})
	require.ErrorIs(t, err, errs.ErrCRLSettingsNotFound, "a CA that cannot sign CRLs gets no CRL settings")

	_, err = serverTest.VA.CRLService.CalculateCRL(ctx, services.CalculateCRLInput{CAID: ca.ID})
	require.ErrorIs(t, err, errs.ErrCRLSettingsNotFound)

	_, err = serverTest.VA.CRLService.GetCRL(ctx, services.GetCRLInput{ID: ca.ID, CRLVersion: big.NewInt(0)})
	require.ErrorIs(t, err, errs.ErrCRLSettingsNotFound)
}
