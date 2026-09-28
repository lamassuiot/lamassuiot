package kms

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/assemblers"
	testassemblers "github.com/lamassuiot/lamassuiot/backend/v3/pkg/assemblers/tests"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/sirupsen/logrus"
)

// TestKMSImportSameKeyInTwoTenants es la prueba A/B de aceptación de 004 T4:
// con la configuración por defecto (un engine filesystem global, sin
// tenant_id) dos tenants importan la misma clave privada sin que el segundo
// import revele que el primero existe.
func TestKMSImportSameKeyInTwoTenants(t *testing.T) {
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
	for _, engine := range cryptoConfig.Config.CryptoEngines {
		if engine.TenantID != "" {
			t.Fatalf("the default engine %s must be global for this test", engine.ID)
		}
	}

	kmsService, err := assemblers.AssembleKMSService(config.KMSConfig{
		Logs:               cconfig.Logging{Level: cconfig.Info},
		Server:             cconfig.HttpServer{LogLevel: cconfig.Info, Protocol: cconfig.HTTP},
		CryptoEngineConfig: cryptoConfig.Config,
		Storage:            storageConfig.Config,
		PublisherEventBus:  cconfig.EventBusEngine{Enabled: false},
	})
	if err != nil {
		t.Fatalf("could not assemble KMS service: %s", err)
	}
	tenantOptions, err := testassemblers.TestTenantRouteOptions(storageConfig.Config)
	if err != nil {
		t.Fatalf("could not build tenant route options: %s", err)
	}
	logger := logrus.NewEntry(logrus.New())
	router := routes.NewGinEngine(logger)
	routes.NewKMSHTTPLayer(logger, router.Group("/"), *kmsService, tenantOptions)
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)

	api := &sameKeyAPI{t: t, baseURL: server.URL}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("could not generate key: %s", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("could not encode key: %s", err)
	}
	importBody := resources.ImportKeyBody{
		PrivateKey: base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})),
		Name:       "same-key",
	}

	status, body := api.do(http.MethodPost, tenantA, "/keys/import", importBody)
	if status != http.StatusCreated {
		t.Fatalf("tenant A import: expected 201, got %d body=%s", status, body)
	}
	var keyA models.Key
	mustDecode(t, body, &keyA)

	status, body = api.do(http.MethodPost, tenantB, "/keys/import", importBody)
	if status != http.StatusCreated {
		t.Fatalf("tenant B import: expected 201, got %d body=%s", status, body)
	}
	var keyB models.Key
	mustDecode(t, body, &keyB)
	if keyA.KeyID == "" || keyA.KeyID != keyB.KeyID {
		t.Fatalf("expected the same key_id in both tenants, got A=%q B=%q", keyA.KeyID, keyB.KeyID)
	}
	if keyA.TenantID != tenantA || keyB.TenantID != tenantB {
		t.Fatalf("each import must belong to its tenant, got A=%q B=%q", keyA.TenantID, keyB.TenantID)
	}
	keyID := keyA.KeyID

	api.mustSignAndVerify(tenantA, keyID, &privateKey.PublicKey)
	api.mustSignAndVerify(tenantB, keyID, &privateKey.PublicKey)

	// B solo ve su propia copia, en el listado y por ID.
	status, body = api.do(http.MethodGet, tenantB, "/keys", nil)
	if status != http.StatusOK {
		t.Fatalf("tenant B list: expected 200, got %d body=%s", status, body)
	}
	var listB resources.GetKeysResponse
	mustDecode(t, body, &listB)
	if len(listB.List) != 1 || listB.List[0].KeyID != keyID || listB.List[0].TenantID != tenantB {
		t.Fatalf("tenant B must list only its own copy, got %+v", listB.List)
	}
	status, body = api.do(http.MethodGet, tenantB, "/keys/"+keyID, nil)
	if status != http.StatusOK {
		t.Fatalf("tenant B get: expected 200, got %d body=%s", status, body)
	}
	var gotB models.Key
	mustDecode(t, body, &gotB)
	if gotB.TenantID != tenantB {
		t.Fatalf("tenant B must get its own copy, got tenant %q", gotB.TenantID)
	}

	// Borrar la copia de B no afecta a A.
	status, body = api.do(http.MethodDelete, tenantB, "/keys/"+keyID, nil)
	if status != http.StatusOK {
		t.Fatalf("tenant B delete: expected 200, got %d body=%s", status, body)
	}
	status, body = api.do(http.MethodGet, tenantB, "/keys/"+keyID, nil)
	if status != http.StatusNotFound {
		t.Fatalf("tenant B get after delete: expected 404, got %d body=%s", status, body)
	}
	api.mustSignAndVerify(tenantA, keyID, &privateKey.PublicKey)

	// Un segundo import en A es un duplicado del propio tenant.
	status, body = api.do(http.MethodPost, tenantA, "/keys/import", importBody)
	if status != http.StatusConflict {
		t.Fatalf("second tenant A import: expected 409, got %d body=%s", status, body)
	}
	api.mustSignAndVerify(tenantA, keyID, &privateKey.PublicKey)

	for _, errorBody := range api.errorBodies {
		for _, leak := range []string{"keys_pkey", "duplicate key", "SQLSTATE", "file exists"} {
			if strings.Contains(errorBody, leak) {
				t.Errorf("error body leaks %q: %s", leak, errorBody)
			}
		}
	}
}

type sameKeyAPI struct {
	t           *testing.T
	baseURL     string
	errorBodies []string
}

func (api *sameKeyAPI) do(method, tenantID, path string, payload any) (int, []byte) {
	api.t.Helper()
	var reader io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			api.t.Fatalf("could not encode request: %s", err)
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequest(method, api.baseURL+"/api/v2/tenants/"+tenantID+path, reader)
	if err != nil {
		api.t.Fatalf("could not build request: %s", err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		api.t.Fatalf("%s %s: %s", method, path, err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		api.t.Fatalf("could not read response: %s", err)
	}
	if response.StatusCode >= 400 {
		api.errorBodies = append(api.errorBodies, string(body))
	}
	return response.StatusCode, body
}

func (api *sameKeyAPI) mustSignAndVerify(tenantID, keyID string, publicKey *ecdsa.PublicKey) {
	api.t.Helper()
	message := []byte("004 T4 " + tenantID)
	status, body := api.do(http.MethodPost, tenantID, "/keys/"+keyID+"/sign", resources.SignMessageBody{
		Algorithm:   "ECDSA_SHA_256",
		Message:     message,
		MessageType: models.Raw,
	})
	if status != http.StatusOK {
		api.t.Fatalf("tenant %s sign: expected 200, got %d body=%s", tenantID, status, body)
	}
	var signature models.MessageSignature
	mustDecode(api.t, body, &signature)
	digest := sha256.Sum256(message)
	if !ecdsa.VerifyASN1(publicKey, digest[:], signature.Signature) {
		api.t.Fatalf("tenant %s signature does not verify with the imported key", tenantID)
	}
}

func mustDecode(t *testing.T, body []byte, target any) {
	t.Helper()
	if err := json.Unmarshal(body, target); err != nil {
		t.Fatalf("could not decode %s: %s", body, err)
	}
}
