package services

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	svcmock "github.com/lamassuiot/lamassuiot/v4/core/pkg/services/mock"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/ocsp"
)

type revocationTestCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newRevocationTestCA(t *testing.T, cn string) *revocationTestCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("could not generate key: %s", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte(cn),
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("could not create CA certificate: %s", err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &revocationTestCA{cert: cert, key: key}
}

func (ca *revocationTestCA) issueLeaf(t *testing.T, serial int64, ocspURLs, crlURLs []string) *x509.Certificate {
	t.Helper()
	return ca.issueLeafWithExtensions(t, serial, ocspURLs, crlURLs, nil)
}

// issueLeafWithExtensions is like issueLeaf, adding exts, such as a CRL distribution points extension crypto/x509
// cannot write.
func (ca *revocationTestCA) issueLeafWithExtensions(t *testing.T, serial int64, ocspURLs, crlURLs []string, exts []pkix.Extension) *x509.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: "device"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		OCSPServer:            ocspURLs,
		CRLDistributionPoints: crlURLs,
		ExtraExtensions:       exts,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("could not create leaf certificate: %s", err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert
}

// issueEndEntity issues a non-CA certificate with the given EKUs and returns it together with its key.
func (ca *revocationTestCA) issueEndEntity(t *testing.T, cn string, ekus []x509.ExtKeyUsage) *revocationTestCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  ekus,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("could not create end-entity certificate: %s", err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &revocationTestCA{cert: cert, key: key}
}

// newTestOCSPResponder serves a response for whatever serial respond returns; status/nextUpdate are taken from respond too.
func newTestOCSPResponder(t *testing.T, ca *revocationTestCA, respond func(reqSerial *big.Int) ocsp.Response) *httptest.Server {
	t.Helper()
	return newTestDelegatedOCSPResponder(t, ca, ca, respond)
}

// newTestDelegatedOCSPResponder is like newTestOCSPResponder but signs with responder, embedding its certificate
// in the response whenever it differs from ca.
func newTestDelegatedOCSPResponder(t *testing.T, ca, responder *revocationTestCA, respond func(reqSerial *big.Int) ocsp.Response) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req, err := ocsp.ParseRequest(body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		tmpl := respond(req.SerialNumber)
		if responder != ca {
			tmpl.Certificate = responder.cert
		}
		resp, err := ocsp.CreateResponse(ca.cert, responder.cert, tmpl, responder.key)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Write(resp)
	}))
}

func crlServer(t *testing.T, signer *revocationTestCA, nextUpdate time.Time, revoked ...*big.Int) *httptest.Server {
	t.Helper()
	return crlServerWithExtensions(t, signer, nextUpdate, nil, revoked...)
}

// crlServerWithExtensions serves a CRL carrying the extensions returned by exts, which receives the server URL so
// that extensions such as IssuingDistributionPoint can reference it.
func crlServerWithExtensions(t *testing.T, signer *revocationTestCA, nextUpdate time.Time, exts func(srvURL string) []pkix.Extension, revoked ...*big.Int) *httptest.Server {
	t.Helper()
	entries := []x509.RevocationListEntry{}
	for _, sn := range revoked {
		// Use a distinct big.Int instance so that pointer comparisons cannot match by accident.
		entries = append(entries, x509.RevocationListEntry{SerialNumber: new(big.Int).Set(sn), RevocationTime: time.Now().Add(-time.Minute)})
	}

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tmpl := &x509.RevocationList{
			Number:                    big.NewInt(1),
			ThisUpdate:                time.Now().Add(-2 * time.Hour),
			NextUpdate:                nextUpdate,
			RevokedCertificateEntries: entries,
		}
		if exts != nil {
			tmpl.ExtraExtensions = exts(srv.URL)
		}
		der, err := x509.CreateRevocationList(rand.Reader, tmpl, signer.cert, signer.key)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Write(der)
	}))
	return srv
}

func idpExtension(t *testing.T, idp issuingDistributionPoint) []pkix.Extension {
	t.Helper()
	value, err := asn1.Marshal(idp)
	if err != nil {
		t.Fatalf("could not marshal issuing distribution point: %s", err)
	}
	return []pkix.Extension{{Id: oidExtensionIssuingDistributionPoint, Critical: true, Value: value}}
}

func uriDistributionPoint(uri string) issuingDistributionPointName {
	return issuingDistributionPointName{FullName: []asn1.RawValue{{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte(uri)}}}
}

// testDistributionPoint is a DistributionPoint of a certificate (RFC 5280 4.2.1.13). Reasons holds the full encoding of
// the [1] ReasonFlags field, so that tests can also write a malformed one.
type testDistributionPoint struct {
	DistributionPoint issuingDistributionPointName `asn1:"optional,tag:0"`
	Reasons           asn1.RawValue                `asn1:"optional"`
}

var (
	// keyCompromiseOnlyReasons is [1] BIT STRING with only keyCompromise (bit 1) set.
	keyCompromiseOnlyReasons = asn1.RawValue{FullBytes: []byte{0x81, 0x02, 0x06, 0x40}}
	// malformedReasons is [1] BIT STRING with no content, which DER forbids.
	malformedReasons = asn1.RawValue{FullBytes: []byte{0x81, 0x00}}
)

func cdpExtension(t *testing.T, dps ...testDistributionPoint) []pkix.Extension {
	t.Helper()
	value, err := asn1.Marshal(dps)
	if err != nil {
		t.Fatalf("could not marshal CRL distribution points: %s", err)
	}
	return []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 31}, Value: value}}
}

func newRevocationTestService(stored *models.Certificate, lookupErr error) DMSManagerServiceBackend {
	caMock := new(svcmock.MockCAService)
	caMock.On("GetCertificateBySerialNumber", mock.Anything, mock.Anything).Return(stored, lookupErr)
	return DMSManagerServiceBackend{
		caClient: caMock,
		logger:   logrus.NewEntry(logrus.New()),
		crlCache: newCRLCache(0, 0),
	}
}

func notInLamassu() DMSManagerServiceBackend {
	return newRevocationTestService((*models.Certificate)(nil), errs.ErrCertificateNotFound)
}

func TestVerifyCertificateNotRevoked(t *testing.T) {
	ca := newRevocationTestCA(t, "external-ca")
	otherCA := newRevocationTestCA(t, "other-ca")

	good := func(sn *big.Int) ocsp.Response {
		return ocsp.Response{Status: ocsp.Good, SerialNumber: sn, ThisUpdate: time.Now().Add(-time.Minute), NextUpdate: time.Now().Add(time.Hour)}
	}

	tests := []struct {
		name              string
		setup             func(t *testing.T) (DMSManagerServiceBackend, *x509.Certificate)
		allowUnverifiable bool
		expectedErr       string
	}{
		{
			name: "OK/ManagedByLamassuActive",
			setup: func(t *testing.T) (DMSManagerServiceBackend, *x509.Certificate) {
				leaf := ca.issueLeaf(t, 10, nil, nil)
				return newRevocationTestService(&models.Certificate{Status: models.StatusActive, Certificate: (*models.X509Certificate)(leaf)}, nil), leaf
			},
		},
		{
			name: "Err/ManagedByLamassuRevoked",
			setup: func(t *testing.T) (DMSManagerServiceBackend, *x509.Certificate) {
				leaf := ca.issueLeaf(t, 11, nil, nil)
				return newRevocationTestService(&models.Certificate{Status: models.StatusRevoked, Certificate: (*models.X509Certificate)(leaf)}, nil), leaf
			},
			allowUnverifiable: true,
			expectedErr:       "certificate is revoked",
		},
		{
			name: "Err/LamassuLookupFails",
			setup: func(t *testing.T) (DMSManagerServiceBackend, *x509.Certificate) {
				return newRevocationTestService((*models.Certificate)(nil), errs.ErrValidateBadRequest), ca.issueLeaf(t, 12, nil, nil)
			},
			allowUnverifiable: true,
			expectedErr:       "could not verify certificate revocation status",
		},
		{
			name: "Err/SerialCollisionWithDifferentStoredCertificate",
			setup: func(t *testing.T) (DMSManagerServiceBackend, *x509.Certificate) {
				stored := otherCA.issueLeaf(t, 13, nil, nil)
				leaf := ca.issueLeaf(t, 13, nil, nil)
				return newRevocationTestService(&models.Certificate{Status: models.StatusActive, Certificate: (*models.X509Certificate)(stored)}, nil), leaf
			},
			expectedErr: "certificate revocation status cannot be verified",
		},
		{
			name: "Err/NoRevocationSourceNotAllowed",
			setup: func(t *testing.T) (DMSManagerServiceBackend, *x509.Certificate) {
				return notInLamassu(), ca.issueLeaf(t, 14, nil, nil)
			},
			expectedErr: "certificate revocation status cannot be verified",
		},
		{
			name: "OK/NoRevocationSourceAllowed",
			setup: func(t *testing.T) (DMSManagerServiceBackend, *x509.Certificate) {
				return notInLamassu(), ca.issueLeaf(t, 15, nil, nil)
			},
			allowUnverifiable: true,
		},
		{
			name: "OK/OCSPGood",
			setup: func(t *testing.T) (DMSManagerServiceBackend, *x509.Certificate) {
				srv := newTestOCSPResponder(t, ca, good)
				t.Cleanup(srv.Close)
				return notInLamassu(), ca.issueLeaf(t, 20, []string{srv.URL}, nil)
			},
		},
		{
			name: "Err/OCSPRevoked",
			setup: func(t *testing.T) (DMSManagerServiceBackend, *x509.Certificate) {
				srv := newTestOCSPResponder(t, ca, func(sn *big.Int) ocsp.Response {
					return ocsp.Response{Status: ocsp.Revoked, SerialNumber: sn, ThisUpdate: time.Now().Add(-time.Minute), RevokedAt: time.Now().Add(-time.Minute)}
				})
				t.Cleanup(srv.Close)
				return notInLamassu(), ca.issueLeaf(t, 21, []string{srv.URL}, nil)
			},
			expectedErr: "certificate is revoked",
		},
		{
			name: "Err/OCSPUnknown",
			setup: func(t *testing.T) (DMSManagerServiceBackend, *x509.Certificate) {
				srv := newTestOCSPResponder(t, ca, func(sn *big.Int) ocsp.Response {
					return ocsp.Response{Status: ocsp.Unknown, SerialNumber: sn, ThisUpdate: time.Now().Add(-time.Minute)}
				})
				t.Cleanup(srv.Close)
				return notInLamassu(), ca.issueLeaf(t, 22, []string{srv.URL}, nil)
			},
			allowUnverifiable: true,
			expectedErr:       "could not verify certificate revocation status",
		},
		{
			name: "Err/OCSPUnreachableEvenIfUnverifiableAllowed",
			setup: func(t *testing.T) (DMSManagerServiceBackend, *x509.Certificate) {
				srv := newTestOCSPResponder(t, ca, good)
				srv.Close()
				return notInLamassu(), ca.issueLeaf(t, 23, []string{srv.URL}, nil)
			},
			allowUnverifiable: true,
			expectedErr:       "could not verify certificate revocation status",
		},
		{
			name: "Err/OCSPResponseForAnotherSerial",
			setup: func(t *testing.T) (DMSManagerServiceBackend, *x509.Certificate) {
				srv := newTestOCSPResponder(t, ca, func(_ *big.Int) ocsp.Response { return good(big.NewInt(9999)) })
				t.Cleanup(srv.Close)
				return notInLamassu(), ca.issueLeaf(t, 24, []string{srv.URL}, nil)
			},
			expectedErr: "could not verify certificate revocation status",
		},
		{
			name: "Err/OCSPStale",
			setup: func(t *testing.T) (DMSManagerServiceBackend, *x509.Certificate) {
				srv := newTestOCSPResponder(t, ca, func(sn *big.Int) ocsp.Response {
					return ocsp.Response{Status: ocsp.Good, SerialNumber: sn, ThisUpdate: time.Now().Add(-2 * time.Hour), NextUpdate: time.Now().Add(-time.Hour)}
				})
				t.Cleanup(srv.Close)
				return notInLamassu(), ca.issueLeaf(t, 25, []string{srv.URL}, nil)
			},
			expectedErr: "could not verify certificate revocation status",
		},
		{
			name: "OK/OCSPWithoutNextUpdateRecent",
			setup: func(t *testing.T) (DMSManagerServiceBackend, *x509.Certificate) {
				srv := newTestOCSPResponder(t, ca, func(sn *big.Int) ocsp.Response {
					return ocsp.Response{Status: ocsp.Good, SerialNumber: sn, ThisUpdate: time.Now().Add(-time.Minute)}
				})
				t.Cleanup(srv.Close)
				return notInLamassu(), ca.issueLeaf(t, 40, []string{srv.URL}, nil)
			},
		},
		{
			// An old "good" response without nextUpdate, recorded before revocation and replayed afterwards.
			name: "Err/OCSPWithoutNextUpdateReplayed",
			setup: func(t *testing.T) (DMSManagerServiceBackend, *x509.Certificate) {
				srv := newTestOCSPResponder(t, ca, func(sn *big.Int) ocsp.Response {
					return ocsp.Response{Status: ocsp.Good, SerialNumber: sn, ThisUpdate: time.Now().Add(-48 * time.Hour)}
				})
				t.Cleanup(srv.Close)
				return notInLamassu(), ca.issueLeaf(t, 41, []string{srv.URL}, nil)
			},
			expectedErr: "could not verify certificate revocation status",
		},
		{
			name: "Err/OCSPThisUpdateInFuture",
			setup: func(t *testing.T) (DMSManagerServiceBackend, *x509.Certificate) {
				srv := newTestOCSPResponder(t, ca, func(sn *big.Int) ocsp.Response {
					return ocsp.Response{Status: ocsp.Good, SerialNumber: sn, ThisUpdate: time.Now().Add(time.Hour), NextUpdate: time.Now().Add(2 * time.Hour)}
				})
				t.Cleanup(srv.Close)
				return notInLamassu(), ca.issueLeaf(t, 42, []string{srv.URL}, nil)
			},
			expectedErr: "could not verify certificate revocation status",
		},
		{
			name: "Err/OCSPStaleRevokedStillHonored",
			setup: func(t *testing.T) (DMSManagerServiceBackend, *x509.Certificate) {
				srv := newTestOCSPResponder(t, ca, func(sn *big.Int) ocsp.Response {
					return ocsp.Response{Status: ocsp.Revoked, SerialNumber: sn, ThisUpdate: time.Now().Add(-48 * time.Hour), RevokedAt: time.Now().Add(-72 * time.Hour)}
				})
				t.Cleanup(srv.Close)
				return notInLamassu(), ca.issueLeaf(t, 43, []string{srv.URL}, nil)
			},
			expectedErr: "certificate is revoked",
		},
		{
			name: "OK/OCSPDelegatedResponderWithOCSPSigningEKU",
			setup: func(t *testing.T) (DMSManagerServiceBackend, *x509.Certificate) {
				responder := ca.issueEndEntity(t, "ocsp-responder", []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning})
				srv := newTestDelegatedOCSPResponder(t, ca, responder, good)
				t.Cleanup(srv.Close)
				return notInLamassu(), ca.issueLeaf(t, 27, []string{srv.URL}, nil)
			},
		},
		{
			// A revoked device forging a "good" response with its own (or a sibling device's) certificate and key.
			name: "Err/OCSPSignedBySiblingCertificateWithoutOCSPSigningEKU",
			setup: func(t *testing.T) (DMSManagerServiceBackend, *x509.Certificate) {
				sibling := ca.issueEndEntity(t, "sibling-device", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
				srv := newTestDelegatedOCSPResponder(t, ca, sibling, good)
				t.Cleanup(srv.Close)
				return notInLamassu(), ca.issueLeaf(t, 28, []string{srv.URL}, nil)
			},
			allowUnverifiable: true,
			expectedErr:       "could not verify certificate revocation status",
		},
		{
			name: "Err/OCSPForgedGoodDoesNotMaskCRLRevocation",
			setup: func(t *testing.T) (DMSManagerServiceBackend, *x509.Certificate) {
				sibling := ca.issueEndEntity(t, "sibling-device", nil)
				ocspSrv := newTestDelegatedOCSPResponder(t, ca, sibling, good)
				crlSrv := crlServer(t, ca, time.Now().Add(time.Hour), big.NewInt(29))
				t.Cleanup(ocspSrv.Close)
				t.Cleanup(crlSrv.Close)
				return notInLamassu(), ca.issueLeaf(t, 29, []string{ocspSrv.URL}, []string{crlSrv.URL})
			},
			expectedErr: "certificate is revoked",
		},
		{
			name: "OK/OCSPUnreachableFallsBackToCRL",
			setup: func(t *testing.T) (DMSManagerServiceBackend, *x509.Certificate) {
				ocspSrv := newTestOCSPResponder(t, ca, good)
				ocspSrv.Close()
				crlSrv := crlServer(t, ca, time.Now().Add(time.Hour))
				t.Cleanup(crlSrv.Close)
				return notInLamassu(), ca.issueLeaf(t, 26, []string{ocspSrv.URL}, []string{crlSrv.URL})
			},
		},
		{
			name: "Err/CRLRevoked",
			setup: func(t *testing.T) (DMSManagerServiceBackend, *x509.Certificate) {
				srv := crlServer(t, ca, time.Now().Add(time.Hour), big.NewInt(30))
				t.Cleanup(srv.Close)
				return notInLamassu(), ca.issueLeaf(t, 30, nil, []string{srv.URL})
			},
			expectedErr: "certificate is revoked",
		},
		{
			name: "OK/CRLNotListed",
			setup: func(t *testing.T) (DMSManagerServiceBackend, *x509.Certificate) {
				srv := crlServer(t, ca, time.Now().Add(time.Hour), big.NewInt(999))
				t.Cleanup(srv.Close)
				return notInLamassu(), ca.issueLeaf(t, 31, nil, []string{srv.URL})
			},
		},
		{
			name: "Err/CRLRevokedInSecondDistributionPoint",
			setup: func(t *testing.T) (DMSManagerServiceBackend, *x509.Certificate) {
				first := crlServer(t, ca, time.Now().Add(time.Hour))
				second := crlServer(t, ca, time.Now().Add(time.Hour), big.NewInt(32))
				t.Cleanup(first.Close)
				t.Cleanup(second.Close)
				return notInLamassu(), ca.issueLeaf(t, 32, nil, []string{first.URL, second.URL})
			},
			expectedErr: "certificate is revoked",
		},
		{
			// CRLs produced by Lamassu's own VA carry a critical IssuingDistributionPoint with only the URL.
			name: "OK/CRLWithLamassuIssuingDistributionPoint",
			setup: func(t *testing.T) (DMSManagerServiceBackend, *x509.Certificate) {
				srv := crlServerWithExtensions(t, ca, time.Now().Add(time.Hour), func(srvURL string) []pkix.Extension {
					ext, err := CRLServiceBackend{vaDomains: []string{strings.TrimPrefix(srvURL, "http://")}}.getDistributionPointExtension("aki", nil)
					if err != nil {
						t.Errorf("could not build Lamassu issuing distribution point: %s", err)
						return nil
					}
					return []pkix.Extension{*ext}
				})
				t.Cleanup(srv.Close)
				return notInLamassu(), ca.issueLeaf(t, 50, nil, []string{srv.URL + "/crl/aki"})
			},
		},
		{
			name: "OK/CRLOnlyContainsUserCerts",
			setup: func(t *testing.T) (DMSManagerServiceBackend, *x509.Certificate) {
				srv := crlServerWithExtensions(t, ca, time.Now().Add(time.Hour), func(srvURL string) []pkix.Extension {
					return idpExtension(t, issuingDistributionPoint{DistributionPoint: uriDistributionPoint(srvURL), OnlyContainsUserCerts: true})
				})
				t.Cleanup(srv.Close)
				return notInLamassu(), ca.issueLeaf(t, 51, nil, []string{srv.URL})
			},
		},
		{
			name: "Err/DeltaCRL",
			setup: func(t *testing.T) (DMSManagerServiceBackend, *x509.Certificate) {
				srv := crlServerWithExtensions(t, ca, time.Now().Add(time.Hour), func(string) []pkix.Extension {
					baseCRLNumber, _ := asn1.Marshal(big.NewInt(1))
					return []pkix.Extension{{Id: oidExtensionDeltaCRLIndicator, Critical: true, Value: baseCRLNumber}}
				})
				t.Cleanup(srv.Close)
				return notInLamassu(), ca.issueLeaf(t, 52, nil, []string{srv.URL})
			},
			expectedErr: "could not verify certificate revocation status",
		},
		{
			name: "Err/DeltaCRLListingCertificateIsStillRevoked",
			setup: func(t *testing.T) (DMSManagerServiceBackend, *x509.Certificate) {
				srv := crlServerWithExtensions(t, ca, time.Now().Add(time.Hour), func(string) []pkix.Extension {
					baseCRLNumber, _ := asn1.Marshal(big.NewInt(1))
					return []pkix.Extension{{Id: oidExtensionDeltaCRLIndicator, Critical: true, Value: baseCRLNumber}}
				}, big.NewInt(53))
				t.Cleanup(srv.Close)
				return notInLamassu(), ca.issueLeaf(t, 53, nil, []string{srv.URL})
			},
			expectedErr: "certificate is revoked",
		},
		{
			name: "Err/CRLOnlyContainsCACerts",
			setup: func(t *testing.T) (DMSManagerServiceBackend, *x509.Certificate) {
				srv := crlServerWithExtensions(t, ca, time.Now().Add(time.Hour), func(srvURL string) []pkix.Extension {
					return idpExtension(t, issuingDistributionPoint{DistributionPoint: uriDistributionPoint(srvURL), OnlyContainsCACerts: true})
				})
				t.Cleanup(srv.Close)
				return notInLamassu(), ca.issueLeaf(t, 54, nil, []string{srv.URL})
			},
			allowUnverifiable: true,
			expectedErr:       "could not verify certificate revocation status",
		},
		{
			name: "Err/CRLOnlySomeReasons",
			setup: func(t *testing.T) (DMSManagerServiceBackend, *x509.Certificate) {
				srv := crlServerWithExtensions(t, ca, time.Now().Add(time.Hour), func(srvURL string) []pkix.Extension {
					keyCompromiseOnly := asn1.BitString{Bytes: []byte{0x40}, BitLength: 2}
					return idpExtension(t, issuingDistributionPoint{DistributionPoint: uriDistributionPoint(srvURL), OnlySomeReasons: keyCompromiseOnly})
				})
				t.Cleanup(srv.Close)
				return notInLamassu(), ca.issueLeaf(t, 55, nil, []string{srv.URL})
			},
			expectedErr: "could not verify certificate revocation status",
		},
		{
			// A present onlySomeReasons with no bit set covers no reason at all (RFC 5280 5.2.5).
			name: "Err/CRLOnlySomeReasonsEmpty",
			setup: func(t *testing.T) (DMSManagerServiceBackend, *x509.Certificate) {
				srv := crlServerWithExtensions(t, ca, time.Now().Add(time.Hour), func(srvURL string) []pkix.Extension {
					noReason := asn1.BitString{Bytes: []byte{}}
					return idpExtension(t, issuingDistributionPoint{DistributionPoint: uriDistributionPoint(srvURL), OnlySomeReasons: noReason})
				})
				t.Cleanup(srv.Close)
				return notInLamassu(), ca.issueLeaf(t, 59, nil, []string{srv.URL})
			},
			expectedErr: "could not verify certificate revocation status",
		},
		{
			// The certificate itself limits the distribution point to some reasons (RFC 5280 6.3.3 (d)).
			name: "Err/CRLDistributionPointLimitsReasons",
			setup: func(t *testing.T) (DMSManagerServiceBackend, *x509.Certificate) {
				srv := crlServer(t, ca, time.Now().Add(time.Hour))
				t.Cleanup(srv.Close)
				cdp := cdpExtension(t, testDistributionPoint{DistributionPoint: uriDistributionPoint(srv.URL), Reasons: keyCompromiseOnlyReasons})
				return notInLamassu(), ca.issueLeafWithExtensions(t, 60, nil, nil, cdp)
			},
			expectedErr: "could not verify certificate revocation status",
		},
		{
			name: "Err/CRLDistributionPointLimitsReasonsListsCertificate",
			setup: func(t *testing.T) (DMSManagerServiceBackend, *x509.Certificate) {
				srv := crlServer(t, ca, time.Now().Add(time.Hour), big.NewInt(61))
				t.Cleanup(srv.Close)
				cdp := cdpExtension(t, testDistributionPoint{DistributionPoint: uriDistributionPoint(srv.URL), Reasons: keyCompromiseOnlyReasons})
				return notInLamassu(), ca.issueLeafWithExtensions(t, 61, nil, nil, cdp)
			},
			expectedErr: "certificate is revoked",
		},
		{
			name: "OK/CRLDistributionPointLimitsReasonsWithCompleteDistributionPoint",
			setup: func(t *testing.T) (DMSManagerServiceBackend, *x509.Certificate) {
				limited := crlServer(t, ca, time.Now().Add(time.Hour))
				t.Cleanup(limited.Close)
				complete := crlServer(t, ca, time.Now().Add(time.Hour))
				t.Cleanup(complete.Close)
				cdp := cdpExtension(t,
					testDistributionPoint{DistributionPoint: uriDistributionPoint(limited.URL), Reasons: keyCompromiseOnlyReasons},
					testDistributionPoint{DistributionPoint: uriDistributionPoint(complete.URL)},
				)
				return notInLamassu(), ca.issueLeafWithExtensions(t, 62, nil, nil, cdp)
			},
		},
		{
			// crypto/x509 never reads the reasons of a distribution point, so it parses this certificate.
			name: "Err/CRLDistributionPointMalformed",
			setup: func(t *testing.T) (DMSManagerServiceBackend, *x509.Certificate) {
				srv := crlServer(t, ca, time.Now().Add(time.Hour))
				t.Cleanup(srv.Close)
				cdp := cdpExtension(t, testDistributionPoint{DistributionPoint: uriDistributionPoint(srv.URL), Reasons: malformedReasons})
				return notInLamassu(), ca.issueLeafWithExtensions(t, 63, nil, nil, cdp)
			},
			expectedErr: "could not verify certificate revocation status",
		},
		{
			name: "Err/CRLIndirect",
			setup: func(t *testing.T) (DMSManagerServiceBackend, *x509.Certificate) {
				srv := crlServerWithExtensions(t, ca, time.Now().Add(time.Hour), func(srvURL string) []pkix.Extension {
					return idpExtension(t, issuingDistributionPoint{DistributionPoint: uriDistributionPoint(srvURL), IndirectCRL: true})
				})
				t.Cleanup(srv.Close)
				return notInLamassu(), ca.issueLeaf(t, 56, nil, []string{srv.URL})
			},
			expectedErr: "could not verify certificate revocation status",
		},
		{
			// A validly signed CRL for another partition of the same CA served in place of the one in the certificate.
			name: "Err/CRLForAnotherPartition",
			setup: func(t *testing.T) (DMSManagerServiceBackend, *x509.Certificate) {
				srv := crlServerWithExtensions(t, ca, time.Now().Add(time.Hour), func(srvURL string) []pkix.Extension {
					return idpExtension(t, issuingDistributionPoint{DistributionPoint: uriDistributionPoint(srvURL + "/partition-2")})
				})
				t.Cleanup(srv.Close)
				return notInLamassu(), ca.issueLeaf(t, 57, nil, []string{srv.URL + "/partition-1"})
			},
			expectedErr: "could not verify certificate revocation status",
		},
		{
			// RFC 5280 6.3.3: the IDP must name one of the certificate's CRL distribution points, not necessarily the
			// one the CRL was downloaded from (mirrors).
			name: "OK/CRLIssuingDistributionPointNamesAnotherDistributionPointOfTheCertificate",
			setup: func(t *testing.T) (DMSManagerServiceBackend, *x509.Certificate) {
				down := httptest.NewServer(http.NotFoundHandler())
				down.Close()
				srv := crlServerWithExtensions(t, ca, time.Now().Add(time.Hour), func(string) []pkix.Extension {
					return idpExtension(t, issuingDistributionPoint{DistributionPoint: uriDistributionPoint(down.URL)})
				})
				t.Cleanup(srv.Close)
				return notInLamassu(), ca.issueLeaf(t, 70, nil, []string{down.URL, srv.URL})
			},
		},
		{
			name: "Err/CRLMalformedIssuingDistributionPoint",
			setup: func(t *testing.T) (DMSManagerServiceBackend, *x509.Certificate) {
				srv := crlServerWithExtensions(t, ca, time.Now().Add(time.Hour), func(string) []pkix.Extension {
					return []pkix.Extension{{Id: oidExtensionIssuingDistributionPoint, Critical: true, Value: []byte{0x30, 0x03, 0x01}}}
				})
				t.Cleanup(srv.Close)
				return notInLamassu(), ca.issueLeaf(t, 58, nil, []string{srv.URL})
			},
			expectedErr: "could not verify certificate revocation status",
		},
		{
			name: "Err/CRLStale",
			setup: func(t *testing.T) (DMSManagerServiceBackend, *x509.Certificate) {
				srv := crlServer(t, ca, time.Now().Add(-time.Hour))
				t.Cleanup(srv.Close)
				return notInLamassu(), ca.issueLeaf(t, 33, nil, []string{srv.URL})
			},
			expectedErr: "could not verify certificate revocation status",
		},
		{
			name: "Err/CRLSignedByAnotherCA",
			setup: func(t *testing.T) (DMSManagerServiceBackend, *x509.Certificate) {
				srv := crlServer(t, otherCA, time.Now().Add(time.Hour))
				t.Cleanup(srv.Close)
				return notInLamassu(), ca.issueLeaf(t, 34, nil, []string{srv.URL})
			},
			allowUnverifiable: true,
			expectedErr:       "could not verify certificate revocation status",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc, leaf := tc.setup(t)
			lFunc := logrus.NewEntry(logrus.New())
			err := svc.verifyCertificateNotRevoked(context.Background(), lFunc, leaf, ca.cert, tc.allowUnverifiable, "enrollment")
			if tc.expectedErr == "" {
				if err != nil {
					t.Fatalf("expected no error. Got %s", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing '%s'. Got none", tc.expectedErr)
			}
			if !strings.Contains(err.Error(), tc.expectedErr) {
				t.Fatalf("expected error containing '%s'. Got %s", tc.expectedErr, err)
			}
		})
	}
}

// TestCheckCertificateRevocationReusesCachedCRL checks that consecutive revocation checks of certificates not managed
// by Lamassu download their CRL once.
func TestCheckCertificateRevocationReusesCachedCRL(t *testing.T) {
	ca := newRevocationTestCA(t, "cached-crl-ca")
	srv, requests := countingServer(t, staticBody(crlDER(t, ca, time.Now().Add(-time.Minute), time.Now().Add(time.Hour), 0)))
	leaf := ca.issueLeaf(t, 500, nil, []string{srv.URL})
	svc := notInLamassu()

	for i := range 2 {
		if err := svc.verifyCertificateNotRevoked(context.Background(), logrus.NewEntry(logrus.New()), leaf, ca.cert, false, "enrollment"); err != nil {
			t.Fatalf("check %d: expected no error. Got %s", i+1, err)
		}
	}
	if n := requests.Load(); n != 1 {
		t.Fatalf("expected 1 CRL download. Got %d", n)
	}
}

func TestCheckRevocationFreshness(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name       string
		thisUpdate time.Time
		nextUpdate time.Time
		fresh      bool
	}{
		{"OK/WithinWindow", now.Add(-time.Hour), now.Add(time.Hour), true},
		{"OK/NextUpdateJustPassedWithinSkew", now.Add(-time.Hour), now.Add(-time.Minute), true},
		{"OK/ThisUpdateSlightlyAheadWithinSkew", now.Add(time.Minute), now.Add(time.Hour), true},
		{"OK/NoNextUpdateRecent", now.Add(-time.Hour), time.Time{}, true},
		{"Err/MissingThisUpdate", time.Time{}, now.Add(time.Hour), false},
		{"Err/ThisUpdateInFuture", now.Add(time.Hour), now.Add(2 * time.Hour), false},
		{"Err/NextUpdatePassed", now.Add(-2 * time.Hour), now.Add(-time.Hour), false},
		{"Err/NoNextUpdateTooOld", now.Add(-25 * time.Hour), time.Time{}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := checkRevocationFreshness(tc.thisUpdate, tc.nextUpdate, now)
			if tc.fresh && err != nil {
				t.Fatalf("expected fresh. Got %s", err)
			}
			if !tc.fresh && err == nil {
				t.Fatalf("expected not fresh. Got no error")
			}
		})
	}
}

// issueSubCA issues an intermediate CA certificate signed by ca, with the given serial and revocation endpoints.
func (ca *revocationTestCA) issueSubCA(t *testing.T, cn string, serial int64, ocspURLs, crlURLs []string) *revocationTestCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte(cn),
		OCSPServer:            ocspURLs,
		CRLDistributionPoints: crlURLs,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("could not create intermediate CA certificate: %s", err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &revocationTestCA{cert: cert, key: key}
}

// TestEnrollmentChainRevocation checks that enrollment verifies the revocation status of every certificate of the
// verified chain against the certificate that signed it, and rejects a validation CA revoked in Lamassu. The DMS
// trusts root; the device presents leaf plus, in most cases, an intermediate issued by root.
func TestEnrollmentChainRevocation(t *testing.T) {
	root := newRevocationTestCA(t, "root-ca")

	good := func(sn *big.Int) ocsp.Response {
		return ocsp.Response{Status: ocsp.Good, SerialNumber: sn, ThisUpdate: time.Now().Add(-time.Minute), NextUpdate: time.Now().Add(time.Hour)}
	}
	crlURL := func(t *testing.T, signer *revocationTestCA, revoked ...*big.Int) string {
		srv := crlServer(t, signer, time.Now().Add(time.Hour), revoked...)
		t.Cleanup(srv.Close)
		return srv.URL
	}
	// goodIntermediate is an intermediate whose root CRL does not list it.
	goodIntermediate := func(t *testing.T) *revocationTestCA {
		return root.issueSubCA(t, "intermediate-ca", 200, nil, []string{crlURL(t, root)})
	}

	tests := []struct {
		name              string
		chain             func(t *testing.T) []*x509.Certificate
		rootStatus        models.CertificateStatus
		allowUnverifiable bool
		expectedErrs      []string
	}{
		{
			name: "OK/OCSPGoodFromIntermediate",
			chain: func(t *testing.T) []*x509.Certificate {
				intermediate := goodIntermediate(t)
				srv := newTestOCSPResponder(t, intermediate, good)
				t.Cleanup(srv.Close)
				return []*x509.Certificate{intermediate.issueLeaf(t, 101, []string{srv.URL}, nil), intermediate.cert}
			},
		},
		{
			name: "OK/CRLFromIntermediateNotListed",
			chain: func(t *testing.T) []*x509.Certificate {
				intermediate := goodIntermediate(t)
				return []*x509.Certificate{intermediate.issueLeaf(t, 102, nil, []string{crlURL(t, intermediate)}), intermediate.cert}
			},
		},
		{
			name: "Err/CRLFromIntermediateListsCertificate",
			chain: func(t *testing.T) []*x509.Certificate {
				intermediate := goodIntermediate(t)
				return []*x509.Certificate{intermediate.issueLeaf(t, 103, nil, []string{crlURL(t, intermediate, big.NewInt(103))}), intermediate.cert}
			},
			expectedErrs: []string{"certificate is revoked"},
		},
		{
			name: "Err/IntermediateRevoked",
			chain: func(t *testing.T) []*x509.Certificate {
				intermediate := root.issueSubCA(t, "intermediate-ca", 201, nil, []string{crlURL(t, root, big.NewInt(201))})
				return []*x509.Certificate{intermediate.issueLeaf(t, 104, nil, []string{crlURL(t, intermediate)}), intermediate.cert}
			},
			expectedErrs: []string{"certificate is revoked", "intermediate-ca", "SN=c9"},
		},
		{
			name: "Err/IntermediateNoSource",
			chain: func(t *testing.T) []*x509.Certificate {
				intermediate := root.issueSubCA(t, "intermediate-ca", 202, nil, nil)
				return []*x509.Certificate{intermediate.issueLeaf(t, 105, nil, []string{crlURL(t, intermediate)}), intermediate.cert}
			},
			expectedErrs: []string{"cannot be verified", "intermediate-ca", "SN=ca"},
		},
		{
			name: "OK/IntermediateNoSourceAllowed",
			chain: func(t *testing.T) []*x509.Certificate {
				intermediate := root.issueSubCA(t, "intermediate-ca", 203, nil, nil)
				return []*x509.Certificate{intermediate.issueLeaf(t, 106, nil, []string{crlURL(t, intermediate)}), intermediate.cert}
			},
			allowUnverifiable: true,
		},
		{
			// A CRL of end-entity certificates only says nothing about an intermediate CA (RFC 5280 6.3.3 (b)(2)(iii)).
			name: "Err/IntermediateCRLOnlyContainsUserCerts",
			chain: func(t *testing.T) []*x509.Certificate {
				srv := crlServerWithExtensions(t, root, time.Now().Add(time.Hour), func(srvURL string) []pkix.Extension {
					return idpExtension(t, issuingDistributionPoint{DistributionPoint: uriDistributionPoint(srvURL), OnlyContainsUserCerts: true})
				})
				t.Cleanup(srv.Close)
				intermediate := root.issueSubCA(t, "intermediate-ca", 204, nil, []string{srv.URL})
				return []*x509.Certificate{intermediate.issueLeaf(t, 110, nil, []string{crlURL(t, intermediate)}), intermediate.cert}
			},
			expectedErrs: []string{"could not verify certificate revocation status", "intermediate-ca"},
		},
		{
			// A CRL of CA certificates only (an ARL) covers an intermediate CA (RFC 5280 6.3.3 (b)(2)(ii)).
			name: "OK/IntermediateCRLOnlyContainsCACerts",
			chain: func(t *testing.T) []*x509.Certificate {
				srv := crlServerWithExtensions(t, root, time.Now().Add(time.Hour), func(srvURL string) []pkix.Extension {
					return idpExtension(t, issuingDistributionPoint{DistributionPoint: uriDistributionPoint(srvURL), OnlyContainsCACerts: true})
				})
				t.Cleanup(srv.Close)
				intermediate := root.issueSubCA(t, "intermediate-ca", 205, nil, []string{srv.URL})
				return []*x509.Certificate{intermediate.issueLeaf(t, 111, nil, []string{crlURL(t, intermediate)}), intermediate.cert}
			},
		},
		{
			name: "OK/ExtraUnrelatedCertificateIgnored",
			chain: func(t *testing.T) []*x509.Certificate {
				intermediate := goodIntermediate(t)
				unrelated := newRevocationTestCA(t, "unrelated-ca")
				return []*x509.Certificate{intermediate.issueLeaf(t, 107, nil, []string{crlURL(t, intermediate)}), unrelated.cert, intermediate.cert}
			},
		},
		{
			name: "OK/LeafDirectlyUnderValidationCA",
			chain: func(t *testing.T) []*x509.Certificate {
				return []*x509.Certificate{root.issueLeaf(t, 108, nil, []string{crlURL(t, root)})}
			},
		},
		{
			name: "Err/ValidationCARevokedInLamassu",
			chain: func(t *testing.T) []*x509.Certificate {
				return []*x509.Certificate{root.issueLeaf(t, 109, nil, []string{crlURL(t, root)})}
			},
			rootStatus:   models.StatusRevoked,
			expectedErrs: []string{"validation CA", "revoked"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			chain := tc.chain(t)
			rootStatus := tc.rootStatus
			if rootStatus == "" {
				rootStatus = models.StatusActive
			}

			caMock := new(svcmock.MockCAService)
			caMock.On("GetCertificateBySerialNumber", mock.Anything, mock.Anything).Return((*models.Certificate)(nil), errs.ErrCertificateNotFound)
			caMock.On("GetCAByID", mock.Anything, mock.Anything).Return(&models.CACertificate{
				ID:          "root-ca",
				Certificate: models.Certificate{Status: rootStatus, Certificate: (*models.X509Certificate)(root.cert)},
			}, nil)
			svc := DMSManagerServiceBackend{caClient: caMock, logger: logrus.NewEntry(logrus.New()), crlCache: newCRLCache(0, 0)}

			opts := models.EnrollmentOptionsESTRFC7030{
				AuthOptionsMTLS: models.AuthOptionsClientCertificate{
					ValidationCAs:               []string{"root-ca"},
					AllowUnverifiableRevocation: tc.allowUnverifiable,
				},
			}
			_, err := svc.validateClientCertificateEnrollment(context.Background(), logrus.NewEntry(logrus.New()), opts, chain)
			if len(tc.expectedErrs) == 0 {
				if err != nil {
					t.Fatalf("expected no error. Got %s", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q. Got none", tc.expectedErrs)
			}
			for _, expected := range tc.expectedErrs {
				if !strings.Contains(err.Error(), expected) {
					t.Fatalf("expected error containing '%s'. Got %s", expected, err)
				}
			}
		})
	}
}

// TestReenrollmentValidationCARevoked checks that re-enrollment rejects a certificate whose validation CA is revoked
// in Lamassu, even when the certificate itself is not revoked.
func TestReenrollmentValidationCARevoked(t *testing.T) {
	enrollCA := newRevocationTestCA(t, "enroll-ca")

	tests := []struct {
		name        string
		status      models.CertificateStatus
		expectedErr string
	}{
		{name: "OK/EnrollCAActive", status: models.StatusActive},
		{name: "Err/EnrollCARevoked", status: models.StatusRevoked, expectedErr: "validation CA enroll-ca is revoked"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := crlServer(t, enrollCA, time.Now().Add(time.Hour))
			t.Cleanup(srv.Close)
			leaf := enrollCA.issueLeaf(t, 301, nil, []string{srv.URL})

			svc := notInLamassu()
			ca := &models.CACertificate{
				ID:          "enroll-ca",
				Certificate: models.Certificate{Status: tc.status, Certificate: (*models.X509Certificate)(enrollCA.cert)},
			}
			_, err := svc.validateClientCertificateReenrollment(context.Background(), logrus.NewEntry(logrus.New()), ca.ID, ca, models.ReEnrollmentSettings{}, []*x509.Certificate{leaf}, leaf.Subject.CommonName)
			if tc.expectedErr == "" {
				if err != nil {
					t.Fatalf("expected no error. Got %s", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.expectedErr) {
				t.Fatalf("expected error containing '%s'. Got %v", tc.expectedErr, err)
			}
		})
	}
}
