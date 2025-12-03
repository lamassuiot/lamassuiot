package controllers

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	svcmock "github.com/lamassuiot/lamassuiot/core/v3/pkg/services/mock"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/ocsp"
)

// MockOCSPService is a mock implementation of the OCSPService interface
type MockOCSPService struct {
	mock.Mock
}

func (m *MockOCSPService) Verify(ctx context.Context, req *ocsp.Request) ([]byte, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

func setupVARouter(ocspService services.OCSPService, crlService services.CRLService) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	logger := logrus.NewEntry(logrus.New())
	vaRoutes := NewVAHttpRoutes(logger, ocspService, crlService)

	router.GET("/va/crl/:ca-ski", vaRoutes.CRL)
	router.GET("/va/role/:ca-ski", vaRoutes.GetRoleByID)
	router.PUT("/va/role/:ca-ski", vaRoutes.UpdateRole)

	return router
}

func TestCRL_Success(t *testing.T) {
	mockCRLService := new(svcmock.MockVAService)
	mockOCSPService := new(MockOCSPService)

	crl := &x509.RevocationList{
		Number: big.NewInt(1),
		Raw:    []byte("mock-crl-data"),
	}

	mockCRLService.On("GetCRL", mock.Anything, mock.MatchedBy(func(input services.GetCRLInput) bool {
		return input.CASubjectKeyID == "test-ca-ski"
	})).Return(crl, nil)

	router := setupVARouter(mockOCSPService, mockCRLService)

	req, _ := http.NewRequest("GET", "/va/crl/test-ca-ski", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/pkix-crl", w.Header().Get("Content-Type"))
	assert.Equal(t, []byte("mock-crl-data"), w.Body.Bytes())
	mockCRLService.AssertExpectations(t)
}

func TestCRL_VARoleNotFound(t *testing.T) {
	mockCRLService := new(svcmock.MockVAService)
	mockOCSPService := new(MockOCSPService)

	mockCRLService.On("GetCRL", mock.Anything, mock.MatchedBy(func(input services.GetCRLInput) bool {
		return input.CASubjectKeyID == "nonexistent-ca-ski"
	})).Return((*x509.RevocationList)(nil), errs.ErrVARoleNotFound)

	router := setupVARouter(mockOCSPService, mockCRLService)

	req, _ := http.NewRequest("GET", "/va/crl/nonexistent-ca-ski", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)

	var response map[string]any
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "VA role not found", response["err"])
	mockCRLService.AssertExpectations(t)
}

func TestCRL_ValidationError(t *testing.T) {
	mockCRLService := new(svcmock.MockVAService)
	mockOCSPService := new(MockOCSPService)

	mockCRLService.On("GetCRL", mock.Anything, mock.Anything).Return((*x509.RevocationList)(nil), errs.ErrValidateBadRequest)

	router := setupVARouter(mockOCSPService, mockCRLService)

	req, _ := http.NewRequest("GET", "/va/crl/invalid", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]any
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "struct validation error", response["err"])
	mockCRLService.AssertExpectations(t)
}

func TestCRL_InternalServerError(t *testing.T) {
	mockCRLService := new(svcmock.MockVAService)
	mockOCSPService := new(MockOCSPService)

	mockCRLService.On("GetCRL", mock.Anything, mock.Anything).Return((*x509.RevocationList)(nil), assert.AnError)

	router := setupVARouter(mockOCSPService, mockCRLService)

	req, _ := http.NewRequest("GET", "/va/crl/test-ca-ski", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	mockCRLService.AssertExpectations(t)
}

func TestGetRoleByID_Success(t *testing.T) {
	mockCRLService := new(svcmock.MockVAService)
	mockOCSPService := new(MockOCSPService)

	bigIntVersion := models.BigInt{Int: big.NewInt(1)}
	vaRole := &models.VARole{
		CASubjectKeyID: "test-ca-ski",
		CRLOptions: models.VACRLRole{
			Validity:           models.TimeDuration(86400000000000), // 24 hours in nanoseconds
			RefreshInterval:    models.TimeDuration(82800000000000), // 23 hours in nanoseconds
			RegenerateOnRevoke: true,
			SubjectKeyIDSigner: "test-ca-ski",
		},
		LatestCRL: models.LatestCRLMeta{
			Version: bigIntVersion,
		},
	}

	mockCRLService.On("GetVARole", mock.Anything, mock.MatchedBy(func(input services.GetVARoleInput) bool {
		return input.CASubjectKeyID == "test-ca-ski"
	})).Return(vaRole, nil)

	router := setupVARouter(mockOCSPService, mockCRLService)

	req, _ := http.NewRequest("GET", "/va/role/test-ca-ski", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Verify response can be parsed
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "test-ca-ski", response["ca_ski"])
	mockCRLService.AssertExpectations(t)
}

func TestGetRoleByID_VARoleNotFound(t *testing.T) {
	mockCRLService := new(svcmock.MockVAService)
	mockOCSPService := new(MockOCSPService)

	mockCRLService.On("GetVARole", mock.Anything, mock.MatchedBy(func(input services.GetVARoleInput) bool {
		return input.CASubjectKeyID == "nonexistent-ca-ski"
	})).Return((*models.VARole)(nil), errs.ErrVARoleNotFound)

	router := setupVARouter(mockOCSPService, mockCRLService)

	req, _ := http.NewRequest("GET", "/va/role/nonexistent-ca-ski", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)

	var response map[string]any
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "VA role not found", response["err"])
	mockCRLService.AssertExpectations(t)
}

func TestGetRoleByID_ValidationError(t *testing.T) {
	mockCRLService := new(svcmock.MockVAService)
	mockOCSPService := new(MockOCSPService)

	mockCRLService.On("GetVARole", mock.Anything, mock.Anything).Return((*models.VARole)(nil), errs.ErrValidateBadRequest)

	router := setupVARouter(mockOCSPService, mockCRLService)

	req, _ := http.NewRequest("GET", "/va/role/invalid", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]any
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "struct validation error", response["err"])
	mockCRLService.AssertExpectations(t)
}

func TestGetRoleByID_InternalServerError(t *testing.T) {
	mockCRLService := new(svcmock.MockVAService)
	mockOCSPService := new(MockOCSPService)

	mockCRLService.On("GetVARole", mock.Anything, mock.Anything).Return((*models.VARole)(nil), assert.AnError)

	router := setupVARouter(mockOCSPService, mockCRLService)

	req, _ := http.NewRequest("GET", "/va/role/test-ca-ski", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	mockCRLService.AssertExpectations(t)
}

func TestUpdateRole_Success(t *testing.T) {
	mockCRLService := new(svcmock.MockVAService)
	mockOCSPService := new(MockOCSPService)

	bigIntVersion := models.BigInt{Int: big.NewInt(1)}
	updatedRole := &models.VARole{
		CASubjectKeyID: "test-ca-ski",
		CRLOptions: models.VACRLRole{
			Validity:           models.TimeDuration(172800000000000), // 48 hours in nanoseconds
			RefreshInterval:    models.TimeDuration(169200000000000), // 47 hours in nanoseconds
			RegenerateOnRevoke: false,
			SubjectKeyIDSigner: "test-ca-ski",
		},
		LatestCRL: models.LatestCRLMeta{
			Version: bigIntVersion,
		},
	}

	mockCRLService.On("UpdateVARole", mock.Anything, mock.MatchedBy(func(input services.UpdateVARoleInput) bool {
		return input.CASubjectKeyID == "test-ca-ski"
	})).Return(updatedRole, nil)

	router := setupVARouter(mockOCSPService, mockCRLService)

	updateBody := resources.VARoleUpdate{
		VACRLRole: models.VACRLRole{
			Validity:           models.TimeDuration(172800000000000),
			RefreshInterval:    models.TimeDuration(169200000000000),
			RegenerateOnRevoke: false,
			SubjectKeyIDSigner: "test-ca-ski",
		},
	}
	bodyBytes, _ := json.Marshal(updateBody)

	req, _ := http.NewRequest("PUT", "/va/role/test-ca-ski", bytes.NewBuffer(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Verify response can be parsed
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "test-ca-ski", response["ca_ski"])

	// Verify CRL options
	crlOptions := response["crl_options"].(map[string]interface{})
	assert.False(t, crlOptions["regenerate_on_revoke"].(bool))

	mockCRLService.AssertExpectations(t)
}

func TestUpdateRole_VARoleNotFound(t *testing.T) {
	mockCRLService := new(svcmock.MockVAService)
	mockOCSPService := new(MockOCSPService)

	mockCRLService.On("UpdateVARole", mock.Anything, mock.MatchedBy(func(input services.UpdateVARoleInput) bool {
		return input.CASubjectKeyID == "nonexistent-ca-ski"
	})).Return((*models.VARole)(nil), errs.ErrVARoleNotFound)

	router := setupVARouter(mockOCSPService, mockCRLService)

	updateBody := resources.VARoleUpdate{
		VACRLRole: models.VACRLRole{
			Validity:           models.TimeDuration(172800000000000),
			RefreshInterval:    models.TimeDuration(169200000000000),
			RegenerateOnRevoke: false,
			SubjectKeyIDSigner: "test-ca-ski",
		},
	}
	bodyBytes, _ := json.Marshal(updateBody)

	req, _ := http.NewRequest("PUT", "/va/role/nonexistent-ca-ski", bytes.NewBuffer(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "VA role not found", response["err"])
	mockCRLService.AssertExpectations(t)
}

func TestUpdateRole_ValidationError(t *testing.T) {
	mockCRLService := new(svcmock.MockVAService)
	mockOCSPService := new(MockOCSPService)

	mockCRLService.On("UpdateVARole", mock.Anything, mock.Anything).Return((*models.VARole)(nil), errs.ErrValidateBadRequest)

	router := setupVARouter(mockOCSPService, mockCRLService)

	updateBody := resources.VARoleUpdate{
		VACRLRole: models.VACRLRole{
			Validity:           models.TimeDuration(172800000000000),
			RefreshInterval:    models.TimeDuration(169200000000000),
			RegenerateOnRevoke: false,
			SubjectKeyIDSigner: "test-ca-ski",
		},
	}
	bodyBytes, _ := json.Marshal(updateBody)

	req, _ := http.NewRequest("PUT", "/va/role/invalid", bytes.NewBuffer(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "struct validation error", response["err"])
	mockCRLService.AssertExpectations(t)
}

func TestUpdateRole_InternalServerError(t *testing.T) {
	mockCRLService := new(svcmock.MockVAService)
	mockOCSPService := new(MockOCSPService)

	mockCRLService.On("UpdateVARole", mock.Anything, mock.Anything).Return((*models.VARole)(nil), assert.AnError)

	router := setupVARouter(mockOCSPService, mockCRLService)

	updateBody := resources.VARoleUpdate{
		VACRLRole: models.VACRLRole{
			Validity:           models.TimeDuration(172800000000000),
			RefreshInterval:    models.TimeDuration(169200000000000),
			RegenerateOnRevoke: false,
			SubjectKeyIDSigner: "test-ca-ski",
		},
	}
	bodyBytes, _ := json.Marshal(updateBody)

	req, _ := http.NewRequest("PUT", "/va/role/test-ca-ski", bytes.NewBuffer(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	mockCRLService.AssertExpectations(t)
}

func TestUpdateRole_InvalidJSON(t *testing.T) {
	mockCRLService := new(svcmock.MockVAService)
	mockOCSPService := new(MockOCSPService)

	router := setupVARouter(mockOCSPService, mockCRLService)

	req, _ := http.NewRequest("PUT", "/va/role/test-ca-ski", bytes.NewBuffer([]byte("invalid-json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}
