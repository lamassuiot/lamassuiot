package migrations38to40

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/backend/pkg/assemblers/tests"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/stretchr/testify/require"
	"gocloud.dev/blob"
	_ "gocloud.dev/blob/fileblob"
)

const (
	// vaBucketDir is where the VA of the test harness keeps its CRLs (FilesystemStorage in tests.BuildVATestServer).
	vaBucketDir = "/tmp/lamassuiot"
	// cdpPrefix is the CRL distribution point the CA writes in what it issues (VAServerDomains in
	// tests.BuildCATestServer), followed by the id of the issuing CA.
	cdpPrefix = "http://dev.lamassu.test/api/va/crl/"
)

// write38CRL publishes the CRL a 3.8 VA would have left for a CA: number 1, signed by the CA, stored in the VA bucket
// under the CA's SKI, where 3.8.1 wrote it (pki/va/crl/<SKI>/<number>.crl, PEM).
func (e *env) write38CRL(fx fixtureCA) *x509.RevocationList {
	e.t.Helper()
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-time.Hour),
		NextUpdate: time.Now().Add(7 * 24 * time.Hour),
	}, fx.Cert, fx.Key)
	require.NoError(e.t, err)
	crl, err := x509.ParseRevocationList(der)
	require.NoError(e.t, err)

	// fileblob requires the bucket directory to exist; on a fresh CI runner nothing has created it yet.
	require.NoError(e.t, os.MkdirAll(vaBucketDir, 0o750))
	ctx := context.Background()
	bucket, err := blob.OpenBucket(ctx, fmt.Sprintf("file://%s?no_tmp_dir", vaBucketDir))
	require.NoError(e.t, err)
	key := fmt.Sprintf("pki/va/crl/%s/1.crl", fx.SKI)
	require.NoError(e.t, bucket.WriteAll(ctx, key, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}), nil))
	e.t.Cleanup(func() {
		_ = bucket.Delete(context.Background(), key)
		_ = bucket.Close()
		_ = os.Remove(filepath.Join(vaBucketDir, "pki", "va", "crl", fx.SKI)) // fileblob leaves the directory behind
	})
	return crl
}

// downloadCRL fetches a CRL as a relying party does, from the public GET /crl/:id of the VA, and checks that the issuer
// signed it.
func downloadCRL(t *testing.T, srv *tests.TestServer, id string, issuer *x509.Certificate) *x509.RevocationList {
	t.Helper()
	crl, err := srv.VA.HttpVASDK.GetCRL(context.Background(), services.GetCRLResponseInput{ID: id, Issuer: issuer, VerifyResponse: true})
	require.NoError(t, err, "download CRL /crl/%s", id)
	return crl
}

// requireCRLAtCDP follows the CRL distribution point of a revoked certificate: it must name the issuing CA, and the CRL
// downloaded there must be signed by the issuer and list the certificate.
func requireCRLAtCDP(t *testing.T, srv *tests.TestServer, revoked *x509.Certificate, issuerID string, issuer *x509.Certificate, serial string) {
	t.Helper()
	require.Len(t, revoked.CRLDistributionPoints, 1, "CDPs of %s", revoked.Subject.CommonName)
	cdp := revoked.CRLDistributionPoints[0]
	require.True(t, strings.HasPrefix(cdp, cdpPrefix), "CDP of %s: %s", revoked.Subject.CommonName, cdp)
	u, err := url.Parse(cdp)
	require.NoError(t, err)
	id, err := url.PathUnescape(path.Base(u.EscapedPath()))
	require.NoError(t, err)
	require.Equal(t, issuerID, id, "the CDP of %s names its issuer", revoked.Subject.CommonName)

	crl := downloadCRL(t, srv, id, issuer)
	require.Contains(t, revokedSerials(crl), serial, "CRL at the CDP of %s", revoked.Subject.CommonName)
}
