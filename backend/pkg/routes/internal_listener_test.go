package routes

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	tenantcontext "github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes/middlewares/tenant-context"
	"github.com/lamassuiot/lamassuiot/core/v3"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	sdk "github.com/lamassuiot/lamassuiot/sdk/v3"
	"github.com/sirupsen/logrus"
)

type internalListenerRepo struct{ lookups int }

func (repo *internalListenerRepo) FindActiveMembership(context.Context, string, string, string) (*models.Membership, *models.Tenant, error) {
	repo.lookups++
	return nil, nil, storage.ErrActiveMembershipNotFound
}

func (repo *internalListenerRepo) GetActiveTenant(_ context.Context, tenantID string) (*models.Tenant, error) {
	if tenantID != "tenant-a" {
		return nil, storage.ErrActiveMembershipNotFound
	}
	return &models.Tenant{ID: "tenant-a", OrganizationID: "org-a", Status: models.TenantActive}, nil
}

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T, name string) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return testCA{cert: cert, key: key}
}

func (ca testCA) issue(t *testing.T, commonName string, serial int64) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: commonName},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	pair, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

func writePEM(t *testing.T, dir, name, blockType string, der []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func TestInternalListenerGrantsServiceIdentityOnlyWithInternalCertificates(t *testing.T) {
	gin.SetMode(gin.TestMode)
	dir := t.TempDir()
	internalCA := newTestCA(t, "lamassu-internal-ca")
	otherCA := newTestCA(t, "other-ca")
	serverCert := internalCA.issue(t, "localhost", 2)
	serviceCert := internalCA.issue(t, "va", 3)
	foreignCert := otherCA.issue(t, "va", 4)

	keyDER, _ := x509.MarshalPKCS8PrivateKey(serverCert.PrivateKey)
	certFile := writePEM(t, dir, "server.pem", "CERTIFICATE", serverCert.Certificate[0])
	keyFile := writePEM(t, dir, "server.key", "PRIVATE KEY", keyDER)
	caFile := writePEM(t, dir, "internal-ca.pem", "CERTIFICATE", internalCA.cert.Raw)

	repo := &internalListenerRepo{}
	engine := gin.New()
	options := TenantRouteOptions{
		Memberships:      repo,
		IdentityProvider: tenantcontext.HTTPIdentityProvider,
		Authorization:    tenantcontext.NewPermissionAuthorizationEngine(),
		RateLimit:        cconfig.HttpServerTenantRateLimit{Enabled: true, RequestsPerSecond: 0.001, Burst: 1},
	}
	engine.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(context.WithValue(c.Request.Context(), core.LamassuContextKeyHTTPRequest, c.Request))
		c.Next()
	})
	_, v2 := TenantAwareGroups(engine.Group("/"), options)
	PermissionGroup(v2, "certificate.issue", options.Authorization).GET("/probe", func(c *gin.Context) {
		tenantContext, err := core.RequireTenantContext(c.Request.Context())
		if err != nil {
			c.Status(http.StatusInternalServerError)
			return
		}
		c.String(http.StatusOK, tenantContext.ActorType+"/"+tenantContext.ActorID+"/"+tenantContext.TenantID)
	})

	internalPort := freePort(t)
	port, shutdown, err := RunHttpRouterWithShutdown(logrus.NewEntry(logrus.New()), engine, cconfig.HttpServer{
		ListenAddress: "127.0.0.1", Protocol: cconfig.HTTP,
		InternalListener: cconfig.HttpServerInternalListener{Enabled: true, Port: internalPort, CertFile: certFile, KeyFile: keyFile, ClientCAFile: caFile},
	}, models.APIServiceInfo{Version: "test"})
	if err != nil {
		t.Fatalf("could not start servers: %s", err)
	}
	t.Cleanup(func() { _ = shutdown() })

	roots := x509.NewCertPool()
	roots.AddCert(internalCA.cert)
	client := func(certificates ...tls.Certificate) *http.Client {
		return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: certificates, MinVersion: tls.VersionTLS12}}}
	}
	internalURL := fmt.Sprintf("https://127.0.0.1:%d/api/v2/tenants/%%s/probe", internalPort)

	for i := 0; i < 3; i++ {
		response, err := client(serviceCert).Get(fmt.Sprintf(internalURL, "tenant-a"))
		if err != nil {
			t.Fatalf("internal call failed: %s", err)
		}
		body := make([]byte, 128)
		n, _ := response.Body.Read(body)
		response.Body.Close()
		if response.StatusCode != http.StatusOK || string(body[:n]) != "INTERNAL_SERVICE/va/tenant-a" {
			t.Fatalf("internal call %d: got %d %q", i, response.StatusCode, body[:n])
		}
	}
	if repo.lookups != 0 {
		t.Fatalf("internal calls must not look up memberships, got %d lookups", repo.lookups)
	}

	// The SDK client configured as the chart renders it (auth_mode mtls,
	// mtls_options and ca_cert_file) reaches the internal listener.
	serviceKeyDER, _ := x509.MarshalPKCS8PrivateKey(serviceCert.PrivateKey)
	sdkClient, err := sdk.BuildHTTPClient(cconfig.HTTPClient{
		AuthMode: cconfig.MTLS,
		AuthMTLSOptions: cconfig.AuthMTLSOptions{
			CertFile: writePEM(t, dir, "va.pem", "CERTIFICATE", serviceCert.Certificate[0]),
			KeyFile:  writePEM(t, dir, "va.key", "PRIVATE KEY", serviceKeyDER),
		},
		HTTPConnection: cconfig.HTTPConnection{
			Protocol: cconfig.HTTPS,
			BasicConnection: cconfig.BasicConnection{
				Hostname: "127.0.0.1", Port: internalPort,
				TLSConfig: cconfig.TLSConfig{CACertificateFile: caFile},
			},
		},
	}, logrus.NewEntry(logrus.New()))
	if err != nil {
		t.Fatalf("could not build SDK client: %s", err)
	}
	sdkResponse, err := sdkClient.Get(fmt.Sprintf(internalURL, "tenant-a"))
	if err != nil {
		t.Fatalf("SDK client could not reach the internal listener: %s", err)
	}
	sdkResponse.Body.Close()
	if sdkResponse.StatusCode != http.StatusOK {
		t.Fatalf("SDK client got %d on the internal listener", sdkResponse.StatusCode)
	}

	response, err := client(serviceCert).Get(fmt.Sprintf(internalURL, "tenant-unknown"))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("unknown tenant on the internal listener: expected 403, got %d", response.StatusCode)
	}

	if _, err := client(foreignCert).Get(fmt.Sprintf(internalURL, "tenant-a")); err == nil {
		t.Fatal("a certificate from another CA must fail the TLS handshake")
	}
	if _, err := client().Get(fmt.Sprintf(internalURL, "tenant-a")); err == nil {
		t.Fatal("a call without client certificate must fail the TLS handshake")
	}

	// The public listener never grants the internal identity, whatever the
	// request carries.
	request, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/api/v2/tenants/tenant-a/probe", port), nil)
	request.Header.Set("X-Forwarded-Client-Cert", "Cert=\"spoofed\"")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the public listener must not accept internal service calls, got %d", response.StatusCode)
	}
}
