package controllers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/stretchr/testify/require"
)

type keyLookupTestService struct {
	services.KMSService
	inputs []services.GetKeysByPublicKeyInput
}

func (svc *keyLookupTestService) GetKeysByPublicKey(_ context.Context, input services.GetKeysByPublicKeyInput) ([]*models.Key, error) {
	svc.inputs = append(svc.inputs, input)
	return []*models.Key{}, nil
}

func postKeyLookup(t *testing.T, svc services.KMSService, body string) int {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/v1/keys/lookup", NewKMSHttpRoutes(svc).GetKeysByPublicKey)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/keys/lookup", strings.NewReader(body)))
	return recorder.Code
}

func TestGetKeysByPublicKeyRejectsMalformedPublicKeys(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	require.NoError(t, err)
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

	for name, body := range map[string]string{
		"not JSON":               `not-json`,
		"empty public key":       `{"public_key": ""}`,
		"not base64":             `{"public_key": "%%%"}`,
		"base64 but not PEM":     `{"public_key": "` + b64("hello") + `"}`,
		"a certificate, not key": `{"public_key": "` + b64(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))) + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			svc := &keyLookupTestService{}
			require.Equal(t, http.StatusBadRequest, postKeyLookup(t, svc, body))
			require.Empty(t, svc.inputs, "a malformed key must not reach the service")
		})
	}
}

func TestGetKeysByPublicKeyPassesTheParsedKeyAndEngine(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	spki, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki})

	svc := &keyLookupTestService{}
	status := postKeyLookup(t, svc, `{"public_key": "`+base64.StdEncoding.EncodeToString(keyPEM)+`", "engine_id": "vault-1"}`)

	require.Equal(t, http.StatusOK, status)
	require.Len(t, svc.inputs, 1)
	require.Equal(t, "vault-1", svc.inputs[0].EngineID)
	require.True(t, priv.PublicKey.Equal(svc.inputs[0].PublicKey))
}
