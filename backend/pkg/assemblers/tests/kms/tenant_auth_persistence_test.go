package kms

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/assemblers"
	testassemblers "github.com/lamassuiot/lamassuiot/backend/v3/pkg/assemblers/tests"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes"
	identityextractors "github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes/middlewares/identity-extractors"
	tenantcontext "github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes/middlewares/tenant-context"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/storage/builder"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/sirupsen/logrus"
)

func TestKMSHTTPSJWTAndMTLSPersistsTenantKey(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tenantA := "00000000-0000-0000-0000-00000000000a"
	tenantB := "00000000-0000-0000-0000-00000000000b"
	storageConfig, err := testassemblers.PreparePostgresForTest([]string{"kms"}, tenantA, tenantB)
	if err != nil {
		t.Fatalf("could not prepare PostgreSQL: %s", err)
	}
	t.Cleanup(storageConfig.AfterSuite)
	if err := storageConfig.BeforeEach(); err != nil {
		t.Fatalf("could not seed PostgreSQL: %s", err)
	}

	cryptoConfig := testassemblers.PrepareCryptoEnginesForTest([]testassemblers.CryptoEngine{testassemblers.GOLANG})
	t.Cleanup(cryptoConfig.AfterSuite)
	if err := cryptoConfig.BeforeEach(); err != nil {
		t.Fatalf("could not prepare crypto engine: %s", err)
	}

	kmsConfig := config.KMSConfig{
		Logs: cconfig.Logging{Level: cconfig.Info},
		Server: cconfig.HttpServer{
			LogLevel: cconfig.Info,
			Protocol: cconfig.HTTP,
		},
		CryptoEngineConfig: cryptoConfig.Config,
		Storage:            storageConfig.Config,
		PublisherEventBus:  cconfig.EventBusEngine{Enabled: false},
	}
	kmsService, err := assemblers.AssembleKMSService(kmsConfig)
	if err != nil {
		t.Fatalf("could not assemble KMS service: %s", err)
	}

	logger := logrus.NewEntry(logrus.New())
	storageEngine, err := builder.BuildStorageEngine(logger, storageConfig.Config)
	if err != nil {
		t.Fatalf("could not build membership storage: %s", err)
	}
	memberships, err := storageEngine.GetControlPlaneMembershipStorage()
	if err != nil {
		t.Fatalf("could not get membership storage: %s", err)
	}

	jwtKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("could not generate JWT signing key: %s", err)
	}
	validator := &identityextractors.JWTValidator{
		KeyFunc: func(token *jwt.Token) (interface{}, error) {
			if token.Method.Alg() != jwt.SigningMethodRS256.Alg() {
				return nil, errors.New("unexpected JWT signing algorithm")
			}
			return &jwtKey.PublicKey, nil
		},
		AllowedIssuers: map[string]struct{}{"test-issuer": {}},
		Audience:       "lamassu-test-api",
		AllowedAlgos:   map[string]struct{}{jwt.SigningMethodRS256.Alg(): {}},
	}
	router := routes.NewGinEngine(logger, validator)
	routes.NewKMSHTTPLayer(logger, router.Group("/"), *kmsService, routes.TenantRouteOptions{
		Memberships:      memberships,
		IdentityProvider: tenantcontext.HTTPIdentityProvider,
		Authorization:    tenantcontext.NewPermissionAuthorizationEngine(),
		Versioning: cconfig.HttpServerVersioning{
			V1DefaultTenantID: tenantA,
			V1SunsetAt:        time.Now().Add(time.Hour),
		},
	})

	// Single-credential policy: tenant routes authenticate with a JWT over HTTPS,
	// while a strict mTLS listener only admits certificate identities, which get
	// no tenant permission grants and cannot be combined with a bearer token.
	tlsFixtures := newTenantAuthTLSFixtures(t)
	serverCertFile, serverKeyFile, caCertFile := writeTenantAuthTLSFiles(t, tlsFixtures)
	jwtServerURL := startTenantAuthServer(t, logger, router, cconfig.HttpServer{
		LogLevel:      cconfig.Info,
		ListenAddress: "127.0.0.1",
		Protocol:      cconfig.HTTPS,
		CertFile:      serverCertFile,
		KeyFile:       serverKeyFile,
	})
	mTLSServerURL := startTenantAuthServer(t, logger, router, cconfig.HttpServer{
		LogLevel:      cconfig.Info,
		ListenAddress: "127.0.0.1",
		Protocol:      cconfig.HTTPS,
		CertFile:      serverCertFile,
		KeyFile:       serverKeyFile,
		Authentication: cconfig.HttpServerAuthentication{
			MutualTLS: cconfig.HttpServerMutualTLSAuthentication{
				Enabled:           true,
				ValidationMode:    cconfig.Strict,
				CACertificateFile: caCertFile,
			},
		},
	})

	client := newTenantAuthHTTPClient(tlsFixtures.roots, tlsFixtures.clientCertificate)
	wrongClient := newTenantAuthHTTPClient(tlsFixtures.roots, tlsFixtures.untrustedClientCertificate)
	noCertificateClient := newTenantAuthHTTPClient(tlsFixtures.roots)
	t.Cleanup(func() {
		client.CloseIdleConnections()
		wrongClient.CloseIdleConnections()
		noCertificateClient.CloseIdleConnections()
	})

	validToken := signTenantAuthJWT(t, jwtKey, map[string]any{
		"iss":        "test-issuer",
		"sub":        "test-kms-client",
		"aud":        "lamassu-test-api",
		"actor_type": "SERVICE",
		"scope":      "key.manage key.read",
		"exp":        time.Now().Add(5 * time.Minute).Unix(),
	})
	invalidJWTKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("could not generate invalid JWT signing key: %s", err)
	}
	invalidToken := signTenantAuthJWT(t, invalidJWTKey, map[string]any{
		"iss":   "test-issuer",
		"sub":   "test-kms-client",
		"aud":   "lamassu-test-api",
		"scope": "key.manage key.read",
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
	})

	createBody, err := json.Marshal(resources.CreateKeyBody{
		Algorithm: "RSA",
		Size:      2048,
		EngineID:  "filesystem-1",
		Name:      "jwt-mtls-persisted-key",
	})
	if err != nil {
		t.Fatalf("could not encode key request: %s", err)
	}
	createURL := jwtServerURL + "/api/v2/tenants/" + tenantA + "/keys"
	response := performTenantAuthRequest(t, noCertificateClient, http.MethodPost, createURL, validToken, createBody)
	responseBody := readTenantAuthResponseBody(t, response)
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("expected authenticated key creation, got status=%d body=%s", response.StatusCode, responseBody)
	}
	var createdKey models.Key
	if err := json.Unmarshal(responseBody, &createdKey); err != nil {
		t.Fatalf("could not decode created key: %s", err)
	}
	if createdKey.KeyID == "" || createdKey.TenantID != tenantA {
		t.Fatalf("created key is missing its ID or tenant scope: %+v", createdKey)
	}

	getURL := jwtServerURL + "/api/v2/tenants/" + tenantA + "/keys/" + createdKey.KeyID
	response = performTenantAuthRequest(t, noCertificateClient, http.MethodGet, getURL, validToken, nil)
	responseBody = readTenantAuthResponseBody(t, response)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected key to be readable from PostgreSQL after creation, got status=%d body=%s", response.StatusCode, responseBody)
	}
	var persistedKey models.Key
	if err := json.Unmarshal(responseBody, &persistedKey); err != nil {
		t.Fatalf("could not decode persisted key: %s", err)
	}
	if persistedKey.KeyID != createdKey.KeyID || persistedKey.TenantID != tenantA {
		t.Fatalf("persisted key has unexpected identity or tenant: %+v", persistedKey)
	}

	otherTenantURL := jwtServerURL + "/api/v2/tenants/" + tenantB + "/keys/" + createdKey.KeyID
	response = performTenantAuthRequest(t, noCertificateClient, http.MethodGet, otherTenantURL, validToken, nil)
	responseBody = readTenantAuthResponseBody(t, response)
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("expected tenant B not to see tenant A key, got status=%d body=%s", response.StatusCode, responseBody)
	}

	response = performTenantAuthRequest(t, noCertificateClient, http.MethodPost, createURL, invalidToken, createBody)
	responseBody = readTenantAuthResponseBody(t, response)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected invalid JWT to be rejected, got status=%d body=%s", response.StatusCode, responseBody)
	}

	response = performTenantAuthRequest(t, noCertificateClient, http.MethodGet, getURL, "", nil)
	responseBody = readTenantAuthResponseBody(t, response)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected request without credentials to be rejected, got status=%d body=%s", response.StatusCode, responseBody)
	}

	mTLSGetURL := mTLSServerURL + "/api/v2/tenants/" + tenantA + "/keys/" + createdKey.KeyID
	response = performTenantAuthRequest(t, client, http.MethodGet, mTLSGetURL, validToken, nil)
	responseBody = readTenantAuthResponseBody(t, response)
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected bearer token combined with client certificate to be rejected, got status=%d body=%s", response.StatusCode, responseBody)
	}

	response = performTenantAuthRequest(t, client, http.MethodGet, mTLSGetURL, "", nil)
	responseBody = readTenantAuthResponseBody(t, response)
	if response.StatusCode == http.StatusOK || bytes.Contains(responseBody, []byte(createdKey.KeyID)) {
		t.Fatalf("expected certificate-only identity without membership to be denied, got status=%d body=%s", response.StatusCode, responseBody)
	}

	if _, err := performTenantAuthRequestWithError(noCertificateClient, http.MethodGet, mTLSGetURL, "", nil); err == nil {
		t.Fatal("expected TLS handshake to reject a missing client certificate")
	}
	if _, err := performTenantAuthRequestWithError(wrongClient, http.MethodGet, mTLSGetURL, "", nil); err == nil {
		t.Fatal("expected TLS handshake to reject a client certificate from an untrusted CA")
	}
}

func startTenantAuthServer(t *testing.T, logger *logrus.Entry, router http.Handler, serverConfig cconfig.HttpServer) string {
	t.Helper()
	port, shutdown, err := routes.RunHttpRouterWithShutdown(logger, router, serverConfig, models.APIServiceInfo{Version: "test"})
	if err != nil {
		t.Fatalf("could not start HTTPS server: %s", err)
	}
	t.Cleanup(func() {
		if err := shutdown(); err != nil {
			t.Errorf("could not stop HTTPS server: %s", err)
		}
	})
	return fmt.Sprintf("https://127.0.0.1:%d", port)
}

type tenantAuthTLSFixtures struct {
	roots                      *x509.CertPool
	caCertificate              *x509.Certificate
	serverCertificate          tls.Certificate
	clientCertificate          tls.Certificate
	untrustedClientCertificate tls.Certificate
}

func newTenantAuthTLSFixtures(t *testing.T) tenantAuthTLSFixtures {
	t.Helper()
	now := time.Now()
	rootCertificate, rootKey := newTenantAuthCA(t, "tenant-auth-test-root", now)
	untrustedRoot, untrustedRootKey := newTenantAuthCA(t, "tenant-auth-untrusted-root", now)
	serverCertificate, _ := newTenantAuthLeafCertificate(t, rootCertificate, rootKey, &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
	})
	clientCertificate, _ := newTenantAuthLeafCertificate(t, rootCertificate, rootKey, &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "test-client"},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
	})
	untrustedClientCertificate, _ := newTenantAuthLeafCertificate(t, untrustedRoot, untrustedRootKey, &x509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject:      pkix.Name{CommonName: "untrusted-client"},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
	})

	roots := x509.NewCertPool()
	roots.AddCert(rootCertificate)
	return tenantAuthTLSFixtures{
		roots:                      roots,
		caCertificate:              rootCertificate,
		serverCertificate:          serverCertificate,
		clientCertificate:          clientCertificate,
		untrustedClientCertificate: untrustedClientCertificate,
	}
}

func writeTenantAuthTLSFiles(t *testing.T, fixtures tenantAuthTLSFixtures) (string, string, string) {
	t.Helper()
	directory := t.TempDir()
	serverCertificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fixtures.serverCertificate.Certificate[0]})
	serverPrivateKeyDER, err := x509.MarshalPKCS8PrivateKey(fixtures.serverCertificate.PrivateKey)
	if err != nil {
		t.Fatalf("could not encode server private key: %s", err)
	}
	serverPrivateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: serverPrivateKeyDER})
	caCertificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fixtures.caCertificate.Raw})
	serverCertificateFile := filepath.Join(directory, "server-cert.pem")
	serverPrivateKeyFile := filepath.Join(directory, "server-key.pem")
	caCertificateFile := filepath.Join(directory, "client-ca.pem")
	for path, contents := range map[string][]byte{
		serverCertificateFile: serverCertificatePEM,
		serverPrivateKeyFile:  serverPrivateKeyPEM,
		caCertificateFile:     caCertificatePEM,
	} {
		if err := os.WriteFile(path, contents, 0600); err != nil {
			t.Fatalf("could not write TLS test file: %s", err)
		}
	}
	return serverCertificateFile, serverPrivateKeyFile, caCertificateFile
}

func newTenantAuthCA(t *testing.T, name string, now time.Time) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("could not generate CA key: %s", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("could not create CA certificate: %s", err)
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		t.Fatalf("could not parse CA certificate: %s", err)
	}
	return certificate, key
}

func newTenantAuthLeafCertificate(t *testing.T, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey, template *x509.Certificate) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("could not generate leaf certificate key: %s", err)
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("could not create leaf certificate: %s", err)
	}
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("could not encode leaf certificate key: %s", err)
	}
	pair, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER}))
	if err != nil {
		t.Fatalf("could not load leaf certificate pair: %s", err)
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		t.Fatalf("could not parse leaf certificate: %s", err)
	}
	return pair, certificate
}

func newTenantAuthHTTPClient(roots *x509.CertPool, certificates ...tls.Certificate) *http.Client {
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion:   tls.VersionTLS12,
		RootCAs:      roots,
		Certificates: certificates,
	}}}
}

func signTenantAuthJWT(t *testing.T, key *rsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()
	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
	if err != nil {
		t.Fatalf("could not sign JWT: %s", err)
	}
	return token
}

func performTenantAuthRequest(t *testing.T, client *http.Client, method, url, token string, body []byte) *http.Response {
	t.Helper()
	response, err := performTenantAuthRequestWithError(client, method, url, token, body)
	if err != nil {
		t.Fatalf("request failed: %s", err)
	}
	return response
}

func readTenantAuthResponseBody(t *testing.T, response *http.Response) []byte {
	t.Helper()
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("could not read response body: %s", err)
	}
	return body
}

func performTenantAuthRequestWithError(client *http.Client, method, url, token string, body []byte) (*http.Response, error) {
	request, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	request.Header.Set("Content-Type", "application/json")
	return client.Do(request)
}
