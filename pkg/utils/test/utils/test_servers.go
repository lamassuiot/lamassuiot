package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/builtin/logical/pki"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/vault"
	"github.com/jakehl/goid"
	clientUtils "github.com/lamassuiot/lamassuiot/pkg/utils/client"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormLogger "gorm.io/gorm/logger"

	alertsRepository "github.com/lamassuiot/lamassuiot/pkg/alerts/server/api/repository/postgres"
	alertsService "github.com/lamassuiot/lamassuiot/pkg/alerts/server/api/service"

	caClient "github.com/lamassuiot/lamassuiot/pkg/ca/client"
	caRepository "github.com/lamassuiot/lamassuiot/pkg/ca/server/api/repository/postgres"
	caService "github.com/lamassuiot/lamassuiot/pkg/ca/server/api/service"
	cryptoEngines "github.com/lamassuiot/lamassuiot/pkg/ca/server/api/service/crypto-engines"
	x509engines "github.com/lamassuiot/lamassuiot/pkg/ca/server/api/service/x509-engines"
	caTransport "github.com/lamassuiot/lamassuiot/pkg/ca/server/api/transport"

	dmsClient "github.com/lamassuiot/lamassuiot/pkg/dms-manager/client"
	dmsRepository "github.com/lamassuiot/lamassuiot/pkg/dms-manager/server/api/repository/postgres"
	dmsService "github.com/lamassuiot/lamassuiot/pkg/dms-manager/server/api/service"
	dmsTransport "github.com/lamassuiot/lamassuiot/pkg/dms-manager/server/api/transport"

	deviceStatsRepository "github.com/lamassuiot/lamassuiot/pkg/device-manager/server/api/repository/badger"
	postgresRepository "github.com/lamassuiot/lamassuiot/pkg/device-manager/server/api/repository/postgres"
	deviceService "github.com/lamassuiot/lamassuiot/pkg/device-manager/server/api/service"
	deviceTransport "github.com/lamassuiot/lamassuiot/pkg/device-manager/server/api/transport"

	estTransport "github.com/lamassuiot/lamassuiot/pkg/est/server/api/transport"

	vaultapi "github.com/hashicorp/vault/api"
	vaulthttp "github.com/hashicorp/vault/http"
	ocspService "github.com/lamassuiot/lamassuiot/pkg/ocsp/server/api/service"
	ocspTransport "github.com/lamassuiot/lamassuiot/pkg/ocsp/server/api/transport"

	"github.com/lamassuiot/lamassuiot/pkg/alerts/server/api/service"
	"github.com/lamassuiot/lamassuiot/pkg/alerts/server/api/service/outputchannels"
	alertsTransport "github.com/lamassuiot/lamassuiot/pkg/alerts/server/api/transport"
)

func BuildCATestServerWithVault(vaultclient *api.Client) (*httptest.Server, *caService.Service, error) {

	dialector := sqlite.Open(fmt.Sprintf("file:%s?mode=memory", goid.NewV4UUID().String()))
	db, err := gorm.Open(dialector, &gorm.Config{
		Logger: gormLogger.Default.LogMode(gormLogger.Silent),
	})
	if err != nil {
		return nil, nil, err
	}

	certificateRepository := caRepository.NewPostgresDB(db)
	var svc caService.Service

	engine, _ := x509engines.NewVaultx509EngineWithClient(vaultclient, "", "pki/lamassu/dev/", "", "", "", "", "http://ocsp.test")
	svc = caService.NewCAService(engine, certificateRepository, "http://ocsp.test", 30, false, "")

	svc = caService.NewInputValudationMiddleware()(svc)

	if err != nil {
		return nil, nil, err
	}

	handler := caTransport.MakeHTTPHandler(svc)

	mux := http.NewServeMux()
	mux.Handle("/v1/", http.StripPrefix("/v1", handler))
	server := httptest.NewUnstartedServer(mux)

	return server, &svc, nil
}

func BuildCATestServer() (*httptest.Server, *caService.Service, error) {

	dialector := sqlite.Open(fmt.Sprintf("file:%s?mode=memory", goid.NewV4UUID().String()))
	db, err := gorm.Open(dialector, &gorm.Config{
		Logger: gormLogger.Default.LogMode(gormLogger.Silent),
	})
	if err != nil {
		return nil, nil, err
	}

	certificateRepository := caRepository.NewPostgresDB(db)
	dir := fmt.Sprintf("/tmp/test/%s", goid.NewV4UUID().String())
	os.RemoveAll(dir)
	os.Mkdir(dir, 0755)
	goPemEngine, _ := cryptoEngines.NewGolangPEMEngine(dir)
	engine := x509engines.NewStandardx509Engine(goPemEngine, "https://ocsp.test")

	var svc caService.Service
	svc = caService.NewCAService(engine, certificateRepository, "http://ocsp.test", 30, false, "")
	svc = caService.NewInputValudationMiddleware()(svc)

	// svc = caService.LoggingMiddleware(logger)(svc)

	handler := caTransport.MakeHTTPHandler(svc)

	mux := http.NewServeMux()
	mux.Handle("/v1/", http.StripPrefix("/v1", handler))
	server := httptest.NewUnstartedServer(mux)

	return server, &svc, nil
}

func BuildDMSManagerTestServer(CATestServer *httptest.Server) (*httptest.Server, dmsService.Service, error) {
	fmt.Sprintf("file:%s?mode=memory", goid.NewV4UUID().String())
	dialector := sqlite.Open(fmt.Sprintf("file:%s?mode=memory", goid.NewV4UUID().String()))
	db, err := gorm.Open(dialector, &gorm.Config{
		Logger: gormLogger.Default.LogMode(gormLogger.Silent),
	})
	if err != nil {
		return nil, nil, err
	}

	dmsRepository := dmsRepository.NewPostgresDB(db)

	CATestServerURL, err := url.Parse(CATestServer.URL)
	if err != nil {
		return nil, nil, err
	}

	lamassuCAClient, err := caClient.NewLamassuCAClient(clientUtils.BaseClientConfigurationuration{
		URL:        CATestServerURL,
		AuthMethod: clientUtils.AuthMethodNone,
	})
	if err != nil {
		return nil, nil, err
	}
	var upstreamKey interface{}
	var svc dmsService.Service
	svc = dmsService.NewDMSManagerService(dmsRepository, &lamassuCAClient, nil, upstreamKey, "")
	svc = dmsService.NewInputValudationMiddleware()(svc)

	handler := dmsTransport.MakeHTTPHandler(svc)

	mux := http.NewServeMux()
	mux.Handle("/v1/", http.StripPrefix("/v1", handler))
	server := httptest.NewUnstartedServer(mux)

	return server, svc, nil
}

func BuildDeviceManagerTestServer(CATestServer *httptest.Server, DMSTestServer *httptest.Server) (*httptest.Server, *deviceService.Service, error) {
	dialector := sqlite.Open(fmt.Sprintf("file:/tmp/%s:memory:", goid.NewV4UUID().String()))
	db, err := gorm.Open(dialector, &gorm.Config{
		Logger: gormLogger.Default.LogMode(gormLogger.Silent),
	})
	if err != nil {
		return nil, nil, err
	}

	deviceRepository := postgresRepository.NewDevicesPostgresDB(db)

	CATestServerURL, err := url.Parse(CATestServer.URL)
	if err != nil {
		return nil, nil, err
	}

	lamassuCAClient, err := caClient.NewLamassuCAClient(clientUtils.BaseClientConfigurationuration{
		URL:        CATestServerURL,
		AuthMethod: clientUtils.AuthMethodNone,
	})
	if err != nil {
		return nil, nil, err
	}

	DMSTestServerURL, err := url.Parse(DMSTestServer.URL)
	if err != nil {
		return nil, nil, err
	}
	lamassuDMSClient, err := dmsClient.NewLamassuDMSManagerClientConfig(clientUtils.BaseClientConfigurationuration{
		URL:        DMSTestServerURL,
		AuthMethod: clientUtils.AuthMethodNone,
	})
	if err != nil {
		return nil, nil, err
	}
	statsRepo, err := deviceStatsRepository.NewStatisticsDBInMemory()
	if err != nil {
		return nil, nil, err
	}
	logsRepo := postgresRepository.NewLogsPostgresDB(db)
	if err != nil {
		return nil, nil, err
	}
	svc := deviceService.NewDeviceManagerService(deviceRepository, logsRepo, statsRepo, 30, lamassuCAClient, lamassuDMSClient)
	svc = deviceService.NewInputValudationMiddleware()(svc)

	handler := deviceTransport.MakeHTTPHandler(svc)
	estHandler := estTransport.MakeHTTPHandler(svc)

	mux := http.NewServeMux()
	mux.Handle("/v1/", http.StripPrefix("/v1", handler))
	mux.Handle("/.well-known/", estHandler)
	server := httptest.NewUnstartedServer(mux)

	return server, &svc, nil
}

func BuildOCSPTestServer(CATestServer *httptest.Server) (*httptest.Server, error) {
	CATestServerURL, err := url.Parse(CATestServer.URL)
	if err != nil {
		return nil, err
	}

	lamassuCAClient, err := caClient.NewLamassuCAClient(clientUtils.BaseClientConfigurationuration{
		URL:        CATestServerURL,
		AuthMethod: clientUtils.AuthMethodNone,
	})
	if err != nil {
		return nil, err
	}

	ocspSigner, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:      []string{"ES"},
			Locality:     []string{"Donostia"},
			Organization: []string{"LAMASSU Foundation"},
			CommonName:   "LAMASSU OCSP",
		},
	}

	crtBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, ocspSigner.Public(), ocspSigner)
	if err != nil {
		panic(err)
	}

	ocspCertificate, err := x509.ParseCertificate(crtBytes)
	if err != nil {
		panic(err)
	}

	svc := ocspService.NewOCSPService(lamassuCAClient, ocspSigner, ocspCertificate)

	handler := ocspTransport.MakeHTTPHandler(svc, false)

	mux := http.NewServeMux()
	mux.Handle("/", handler)
	server := httptest.NewUnstartedServer(mux)

	return server, nil
}

func BuildMailTestServer(jsonTemplate string, smtpConfig outputchannels.SMTPOutputService) (*httptest.Server, *alertsService.Service, error) {
	dialector := sqlite.Open(fmt.Sprintf("file:%s?mode=memory", goid.NewV4UUID().String()))
	db, err := gorm.Open(dialector, &gorm.Config{
		Logger: gormLogger.Default.LogMode(gormLogger.Silent),
	})
	if err != nil {
		return nil, nil, err
	}

	mailRepo := alertsRepository.NewPostgresDB(db)

	var svc alertsService.Service
	svc, err = service.NewAlertsService(mailRepo, jsonTemplate, smtpConfig)
	if err != nil {
		return nil, nil, err
	}
	handler := alertsTransport.MakeHTTPHandler(svc)

	mux := http.NewServeMux()
	mux.Handle("/", handler)
	server := httptest.NewUnstartedServer(mux)

	return server, &svc, nil
}

func NewVaultSecretsMock(t *testing.T) (*api.Client, error) {
	t.Helper()

	appLogger := hclog.New(&hclog.LoggerOptions{
		Name: "my-app",
		// Level:  hclog.LevelFromString("DEBUG"),
		Output: io.Discard,
	})

	coreConfig := &vault.CoreConfig{
		Logger: appLogger,
		LogicalBackends: map[string]logical.Factory{
			"pki": pki.Factory,
		},
	}

	core, keyShares, rootToken := vault.TestCoreUnsealedWithConfig(t, coreConfig)
	_ = keyShares

	_, addr := vaulthttp.TestServer(t, core)

	conf := vaultapi.DefaultConfig()
	conf.Address = strings.ReplaceAll(conf.Address, "https://127.0.0.1:8200", addr)

	client, err := vaultapi.NewClient(conf)
	if err != nil {
		return nil, err
	}
	client.SetToken(rootToken)

	//Mount CA PKI Backend
	_, err = client.Logical().Write("sys/mounts/Lamassu-Root-CA1-RSA4096", map[string]interface{}{
		"type": "pki",
		"config": map[string]interface{}{
			"max_lease_ttl": "262800h",
		},
	})
	if err != nil {
		return nil, err
	}

	//Setup CA Role
	_, err = client.Logical().Write("Lamassu-Root-CA1-RSA4096/roles/enroller", map[string]interface{}{
		"allow_any_name": true,
		"max_ttl":        "262800h",
		"key_type":       "any",
	})
	if err != nil {
		return nil, err
	}

	//Setup CA internal root certificate
	_, err = client.Logical().Write("Lamassu-Root-CA1-RSA4096/root/generate/internal", map[string]interface{}{
		"common_name":  "LKS Next Root CA 1",
		"key_type":     "rsa",
		"key_bits":     "4096",
		"organization": "LKS Next S. Coop",
		"country":      "ES",
		"ttl":          "262800h",
		"province":     "Gipuzkoa",
		"locality":     "Arrasate",
	})
	if err != nil {
		return nil, err
	}
	return client, err
}
