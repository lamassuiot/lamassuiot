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

func newRevocationTestCA(t *testing.T, cn string, parent *revocationTestCA) *revocationTestCA {
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

	signerCert, signerKey := tmpl, key
	if parent != nil {
		signerCert, signerKey = parent.cert, parent.key
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatalf("could not create CA certificate: %s", err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &revocationTestCA{cert: cert, key: key}
}

func (ca *revocationTestCA) issueLeaf(t *testing.T, serial int64, ocspURLs, crlURLs []string) *x509.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: "device"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		OCSPServer:            ocspURLs,
		CRLDistributionPoints: crlURLs,
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
	entries := []x509.RevocationListEntry{}
	for _, sn := range revoked {
		// Use a distinct big.Int instance so that pointer comparisons cannot match by accident.
		entries = append(entries, x509.RevocationListEntry{SerialNumber: new(big.Int).Set(sn), RevocationTime: time.Now().Add(-time.Minute)})
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    big.NewInt(1),
		ThisUpdate:                time.Now().Add(-2 * time.Hour),
		NextUpdate:                nextUpdate,
		RevokedCertificateEntries: entries,
	}, signer.cert, signer.key)
	if err != nil {
		t.Fatalf("could not create CRL: %s", err)
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(der)
	}))
}

func newRevocationTestService(stored *models.Certificate, lookupErr error) DMSManagerServiceBackend {
	caMock := new(svcmock.MockCAService)
	caMock.On("GetCertificateBySerialNumber", mock.Anything, mock.Anything).Return(stored, lookupErr)
	return DMSManagerServiceBackend{
		caClient: caMock,
		logger:   logrus.NewEntry(logrus.New()),
	}
}

func notInLamassu() DMSManagerServiceBackend {
	return newRevocationTestService((*models.Certificate)(nil), errs.ErrCertificateNotFound)
}

func TestVerifyCertificateNotRevoked(t *testing.T) {
	ca := newRevocationTestCA(t, "external-ca", nil)
	otherCA := newRevocationTestCA(t, "other-ca", nil)

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

func TestLeafIssuer(t *testing.T) {
	root := newRevocationTestCA(t, "root", nil)
	intermediate := newRevocationTestCA(t, "intermediate", root)
	unrelated := newRevocationTestCA(t, "unrelated", nil)

	leafFromIntermediate := intermediate.issueLeaf(t, 1, nil, nil)
	if got := leafIssuer(leafFromIntermediate, root.cert, []*x509.Certificate{unrelated.cert, intermediate.cert}); !got.Equal(intermediate.cert) {
		t.Fatalf("expected intermediate as issuer. Got %s", got.Subject.CommonName)
	}

	leafFromRoot := root.issueLeaf(t, 2, nil, nil)
	if got := leafIssuer(leafFromRoot, root.cert, []*x509.Certificate{intermediate.cert}); !got.Equal(root.cert) {
		t.Fatalf("expected validation CA as issuer. Got %s", got.Subject.CommonName)
	}
}
