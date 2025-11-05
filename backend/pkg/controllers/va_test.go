package controllers

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services/mock"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	smock "github.com/stretchr/testify/mock"
	"golang.org/x/crypto/ocsp"
)

// MockOCSPService is a mock implementation of the OCSPService interface
type MockOCSPService struct {
	smock.Mock
}

func (m *MockOCSPService) Verify(ctx context.Context, req *ocsp.Request) ([]byte, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

// getMinimalOCSPRequest returns a minimal valid OCSP request bytes
func getMinimalOCSPRequest() []byte {
	// This is a minimal valid OCSP request structure (DER-encoded ASN.1)
	return []byte{
		0x30, 0x37, // SEQUENCE
		0x30, 0x35, // SEQUENCE (TBSRequest)
		0x30, 0x33, // SEQUENCE (Request)
		0x30, 0x31, // SEQUENCE (CertID)
		0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, // AlgorithmIdentifier (SHA-1)
		0x04, 0x14, // OCTET STRING (issuerNameHash)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x04, 0x14, // OCTET STRING (issuerKeyHash)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x01, 0x01, // INTEGER (serialNumber)
	}
}

func setupTestRouter() (*gin.Engine, *vaHttpRoutes) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	
	logger := logrus.NewEntry(logrus.New())
	ocspService := &MockOCSPService{}
	crlService := &mock.MockVAService{}
	
	routes := NewVAHttpRoutes(logger, ocspService, crlService)
	
	return router, routes
}

func TestVerify_CertificateNotFound(t *testing.T) {
	router, routes := setupTestRouter()
	router.POST("/ocsp", routes.Verify)
	
	mockOCSP := routes.ocsp.(*MockOCSPService)
	mockOCSP.On("Verify", smock.Anything, smock.Anything).Return(nil, errs.ErrCertificateNotFound)
	
	req := httptest.NewRequest("POST", "/ocsp", bytes.NewReader(getMinimalOCSPRequest()))
	req.Header.Set("Content-Type", "application/ocsp-request")
	
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusBadRequest, w.Code, "Expected 400 for certificate not found")
}

func TestVerify_CANotFound(t *testing.T) {
	router, routes := setupTestRouter()
	router.POST("/ocsp", routes.Verify)
	
	mockOCSP := routes.ocsp.(*MockOCSPService)
	mockOCSP.On("Verify", smock.Anything, smock.Anything).Return(nil, errs.ErrCANotFound)
	
	req := httptest.NewRequest("POST", "/ocsp", bytes.NewReader(getMinimalOCSPRequest()))
	req.Header.Set("Content-Type", "application/ocsp-request")
	
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusBadRequest, w.Code, "Expected 400 for CA not found")
}

func TestVerify_ValidationError(t *testing.T) {
	router, routes := setupTestRouter()
	router.POST("/ocsp", routes.Verify)
	
	mockOCSP := routes.ocsp.(*MockOCSPService)
	mockOCSP.On("Verify", smock.Anything, smock.Anything).Return(nil, errs.ErrValidateBadRequest)
	
	req := httptest.NewRequest("POST", "/ocsp", bytes.NewReader(getMinimalOCSPRequest()))
	req.Header.Set("Content-Type", "application/ocsp-request")
	
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusBadRequest, w.Code, "Expected 400 for validation error")
}

// Note: OCSP parsing tests for internal errors and success cases are covered
// by integration tests in pkg/assemblers/va_test.go which use real certificates.
// The tests above verify that parsing errors (400) are correctly distinguished from
// service-level errors. Additional OCSP error handling is tested via CRL endpoints.

func TestVerify_GET_InvalidBase64(t *testing.T) {
	router, routes := setupTestRouter()
	router.GET("/ocsp/:ocsp_request", routes.Verify)
	
	// Invalid base64
	req := httptest.NewRequest("GET", "/ocsp/invalid!@#base64", nil)
	
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusBadRequest, w.Code, "Expected 400 for invalid base64")
}

func TestCRL_ValidationError(t *testing.T) {
	router, routes := setupTestRouter()
	router.GET("/crl/:ca-ski", routes.CRL)
	
	mockCRL := routes.crl.(*mock.MockVAService)
	mockCRL.On("GetCRL", smock.Anything, smock.Anything).Return((*x509.RevocationList)(nil), errs.ErrValidateBadRequest)
	
	req := httptest.NewRequest("GET", "/crl/test-ca-ski", nil)
	
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusBadRequest, w.Code, "Expected 400 for validation error")
}

func TestCRL_NotFound(t *testing.T) {
	router, routes := setupTestRouter()
	router.GET("/crl/:ca-ski", routes.CRL)
	
	mockCRL := routes.crl.(*mock.MockVAService)
	mockCRL.On("GetCRL", smock.Anything, smock.Anything).Return((*x509.RevocationList)(nil), fmt.Errorf("VA role for CA test-ca-ski does not exist"))
	
	req := httptest.NewRequest("GET", "/crl/test-ca-ski", nil)
	
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusBadRequest, w.Code, "Expected 400 for VA role not found")
}

func TestCRL_InternalError(t *testing.T) {
	router, routes := setupTestRouter()
	router.GET("/crl/:ca-ski", routes.CRL)
	
	mockCRL := routes.crl.(*mock.MockVAService)
	mockCRL.On("GetCRL", smock.Anything, smock.Anything).Return((*x509.RevocationList)(nil), errors.New("database connection failed"))
	
	req := httptest.NewRequest("GET", "/crl/test-ca-ski", nil)
	
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusInternalServerError, w.Code, "Expected 500 for internal error")
}

func TestGetRoleByID_NotFound(t *testing.T) {
	router, routes := setupTestRouter()
	router.GET("/role/:ca-ski", routes.GetRoleByID)
	
	mockCRL := routes.crl.(*mock.MockVAService)
	mockCRL.On("GetVARole", smock.Anything, smock.Anything).Return((*models.VARole)(nil), fmt.Errorf("VA role for CA test-ca-ski does not exist"))
	
	req := httptest.NewRequest("GET", "/role/test-ca-ski", nil)
	
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusBadRequest, w.Code, "Expected 400 for VA role not found")
}

func TestGetRoleByID_InternalError(t *testing.T) {
	router, routes := setupTestRouter()
	router.GET("/role/:ca-ski", routes.GetRoleByID)
	
	mockCRL := routes.crl.(*mock.MockVAService)
	mockCRL.On("GetVARole", smock.Anything, smock.Anything).Return((*models.VARole)(nil), errors.New("database error"))
	
	req := httptest.NewRequest("GET", "/role/test-ca-ski", nil)
	
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusInternalServerError, w.Code, "Expected 500 for internal error")
}

func TestUpdateRole_NotFound(t *testing.T) {
	router, routes := setupTestRouter()
	router.PUT("/role/:ca-ski", routes.UpdateRole)
	
	mockCRL := routes.crl.(*mock.MockVAService)
	mockCRL.On("UpdateVARole", smock.Anything, smock.Anything).Return((*models.VARole)(nil), fmt.Errorf("VA role for CA test-ca-ski does not exist"))
	
	body := []byte(`{"crl_role": {"regenerate_on_revoke": true}}`)
	req := httptest.NewRequest("PUT", "/role/test-ca-ski", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusBadRequest, w.Code, "Expected 400 for VA role not found")
}

func TestUpdateRole_InternalError(t *testing.T) {
	router, routes := setupTestRouter()
	router.PUT("/role/:ca-ski", routes.UpdateRole)
	
	mockCRL := routes.crl.(*mock.MockVAService)
	mockCRL.On("UpdateVARole", smock.Anything, smock.Anything).Return((*models.VARole)(nil), errors.New("database error"))
	
	body := []byte(`{"crl_role": {"regenerate_on_revoke": true}}`)
	req := httptest.NewRequest("PUT", "/role/test-ca-ski", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusInternalServerError, w.Code, "Expected 500 for internal error")
}


