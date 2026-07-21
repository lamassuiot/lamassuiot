package cmp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/assemblers/tests"
	dmshelpers "github.com/lamassuiot/lamassuiot/backend/v3/pkg/helpers"
	corecmp "github.com/lamassuiot/lamassuiot/core/v3/pkg/cmp"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Native (non-openssl) IR client helpers, built on core/pkg/cmp.
// ---------------------------------------------------------------------------

// cmpIssueSignerCert provisions a bootstrap CA in Lamassu and issues an EE
// certificate from it, entirely in memory, for use as the CMP message
// protection signer (extraCerts[0] / header.sender). The bootstrap CA's ID is
// returned so the test can wire it into the DMS's AuthOptionsMTLS.ValidationCAs.
func cmpIssueSignerCert(t *testing.T, ctx context.Context, ts *tests.TestServer, signerCN string) (cert *x509.Certificate, signer crypto.Signer, bootstrapCAID string) {
	t.Helper()

	bootstrapCA := cmpCreateCA(t, ctx, ts, "cmp-bootstrap-"+signerCN)

	key, err := chelpers.GenerateECDSAKey(elliptic.P256())
	require.NoError(t, err)
	csr, err := chelpers.GenerateCertificateRequest(models.Subject{CommonName: signerCN}, key)
	require.NoError(t, err)

	issued, err := ts.CA.Service.SignCertificate(ctx, services.SignCertificateInput{
		CAID:              bootstrapCA.ID,
		CertRequest:       (*models.X509CertificateRequest)(csr),
		IssuanceProfileID: bootstrapCA.ProfileID,
	})
	require.NoError(t, err)

	return (*x509.Certificate)(issued.Certificate), key, bootstrapCA.ID
}

// cmpBuildIR builds a signed, protected IR PKIMessage DER using core/pkg/cmp
// builders: a CRMF CertReqMsg with a valid POPOSigningKey proof of possession
// over the device's own new key, protected with the given RA-trusted signer
// certificate/key (mirroring the mTLS client-certificate CMP auth mode).
func cmpBuildIR(t *testing.T, deviceCN string, deviceKey *ecdsa.PrivateKey, signerCert *x509.Certificate, signer crypto.Signer, recipientCN string) []byte {
	t.Helper()

	irBody, err := corecmp.BuildEnrollmentRequest(corecmp.BodyIR, corecmp.EnrollmentRequestOptions{
		Subject:   pkix.Name{CommonName: deviceCN},
		PublicKey: &deviceKey.PublicKey,
		Proof:     corecmp.ProofOfPossessionSignature,
		Signer:    deviceKey,
	})
	require.NoError(t, err)

	recipient, err := corecmp.GeneralNameDirectoryName(pkix.Name{CommonName: recipientCN})
	require.NoError(t, err)
	txID, err := corecmp.NewNonce()
	require.NoError(t, err)
	senderNonce, err := corecmp.NewNonce()
	require.NoError(t, err)

	header := corecmp.Header{
		PVNO:          corecmp.PVNOCMP2000,
		Recipient:     recipient,
		TransactionID: txID,
		SenderNonce:   senderNonce,
		// header.Sender is left empty: MarshalProtectedMessage fills it (and
		// senderKID) from signerCert, matching what a real EE must send when
		// using signature-based protection (RFC 9483 §3.5).
		GeneralInfo: []corecmp.InfoTypeAndValue{
			{InfoType: corecmp.OIDImplicitConfirm(), InfoValue: asn1.NullRawValue},
		},
	}

	derMsg, err := corecmp.MarshalProtected(header, irBody, []*x509.Certificate{signerCert}, signer)
	require.NoError(t, err)
	return derMsg
}

// cmpPostMessage POSTs a DER-encoded CMP PKIMessage directly to the DMS
// manager's well-known CMP endpoint over HTTPS (TLS verification skipped,
// matching every other in-process test server in this suite) and returns the
// parsed response message.
func cmpPostMessage(t *testing.T, ctx context.Context, dmsMgr *tests.DMSManagerTestServer, dmsID string, derMsg []byte) corecmp.ParsedMessage {
	t.Helper()

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402 -- test-only
		},
	}

	url := fmt.Sprintf("https://127.0.0.1:%d/.well-known/cmp/p/%s", dmsMgr.Port, dmsID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(derMsg))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/pkixcmp")

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "response body: %s", body)

	parsed, err := corecmp.ParseMessage(body)
	require.NoError(t, err)
	return parsed
}

// cmpDecodeCertResponse decodes the single CertResponse out of an ip/cp/kup
// CertRepMessage body, returning its PKIStatus and (if present) the issued
// certificate.
func cmpDecodeCertResponse(t *testing.T, body corecmp.EncodedBody) (status corecmp.PKIStatus, cert *x509.Certificate) {
	t.Helper()

	var certRep corecmp.ServerCertRepMessage
	_, err := asn1.Unmarshal(body.DER, &certRep)
	require.NoError(t, err)
	require.Len(t, certRep.Responses, 1)

	response := certRep.Responses[0]
	if len(response.CertifiedKeyPair.FullBytes) == 0 {
		return response.Status.Status, nil
	}

	var certifiedKeyPair struct{ CertOrEncCert asn1.RawValue }
	_, err = asn1.Unmarshal(response.CertifiedKeyPair.FullBytes, &certifiedKeyPair)
	require.NoError(t, err)

	cert, err = x509.ParseCertificate(certifiedKeyPair.CertOrEncCert.Bytes)
	require.NoError(t, err)
	return response.Status.Status, cert
}

// ---------------------------------------------------------------------------
// Happy-path test
// ---------------------------------------------------------------------------

// TestCMPIR_HappyPath drives an Initialization Request end to end through the
// fully wired DMS manager service (StartDMSManagerServiceTestServer), building
// the request with core/pkg/cmp instead of shelling out to openssl. It covers
// the baseline flow only: a pre-registered device submits a valid,
// RA-authenticated ir and the server issues + stores the certificate.
func TestCMPIR_HappyPath(t *testing.T) {
	f := newCMPTestFixture(t)

	signerCert, signerKey, bootstrapCAID := cmpIssueSignerCert(t, f.ctx, f.testServers, "signer-ir-happy-path")

	dms := cmpCreateDMS(t, f.ctx, f.dmsMgr, "cmp-dms-ir-happy-path", f.enrollCA.ID,
		models.EnrollmentOptionsLWCRFC9483{
			AuthMode: models.CMPAuthModeClientCertificate,
			AuthOptionsMTLS: models.AuthOptionsClientCertificate{
				ValidationCAs: []string{bootstrapCAID},
			},
			EnforcePOPO:    true,
			AcceptImplicit: true,
		},
	)

	deviceID := "device-ir-happy-path"
	cmpPreRegisterDevice(t, f.ctx, f.testServers, deviceID, dms.ID)

	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	irDER := cmpBuildIR(t, deviceID, deviceKey, signerCert, signerKey, dms.ID)

	parsed := cmpPostMessage(t, f.ctx, f.dmsMgr, dms.ID, irDER)
	require.Equal(t, corecmp.BodyIP, parsed.Body.Type, "server must reply with an ip body")

	status, issuedCert := cmpDecodeCertResponse(t, parsed.Body)
	assert.Equal(t, corecmp.PKIStatus(corecmp.PKIStatusAccepted), status)
	require.NotNil(t, issuedCert, "accepted ip response must carry the issued certificate")

	assert.Equal(t, deviceID, issuedCert.Subject.CommonName)
	assert.NoError(t, dmshelpers.ValidateCertificate((*x509.Certificate)(f.enrollCA.Certificate.Certificate), issuedCert, true))

	device, err := f.testServers.DeviceManager.Service.GetDeviceByID(f.ctx, services.GetDeviceByIDInput{ID: deviceID})
	require.NoError(t, err)
	require.NotNil(t, device.IdentitySlot)

	serial := device.IdentitySlot.Secrets[device.IdentitySlot.ActiveVersion]
	stored, err := f.testServers.CA.Service.GetCertificateBySerialNumber(f.ctx, services.GetCertificatesBySerialNumberInput{
		SerialNumber: serial,
	})
	require.NoError(t, err)
	assert.Equal(t, issuedCert.Raw, []byte(stored.Certificate.Raw))
}
