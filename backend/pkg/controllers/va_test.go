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
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	svcmock "github.com/lamassuiot/lamassuiot/v4/core/pkg/services/mock"
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

	router.GET("/va/crl/:id", vaRoutes.CRL)
	router.GET("/va/crl-settings", vaRoutes.GetCRLSettingsList)
	router.GET("/va/crl-settings/:ca-id", vaRoutes.GetCRLSettingsByID)
	router.PUT("/va/crl-settings/:ca-id", vaRoutes.UpdateCRLSettings)

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
		return input.ID == "test-ca-ski"
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

func TestCRL_SettingsNotFound(t *testing.T) {
	mockCRLService := new(svcmock.MockVAService)
	mockOCSPService := new(MockOCSPService)

	mockCRLService.On("GetCRL", mock.Anything, mock.MatchedBy(func(input services.GetCRLInput) bool {
		return input.ID == "nonexistent-ca-ski"
	})).Return((*x509.RevocationList)(nil), errs.ErrCRLSettingsNotFound)

	router := setupVARouter(mockOCSPService, mockCRLService)

	req, _ := http.NewRequest("GET", "/va/crl/nonexistent-ca-ski", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)

	var response map[string]any
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "CRL settings not found", response["err"])
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

func TestGetCRLSettingsByID_Success(t *testing.T) {
	mockCRLService := new(svcmock.MockVAService)
	mockOCSPService := new(MockOCSPService)

	bigIntVersion := models.BigInt{Int: big.NewInt(1)}
	vaRole := &models.CRLSettings{
		CAID: "test-ca-ski",
		Options: models.CRLSettingsOptions{
			Validity:           models.TimeDuration(24 * time.Hour),
			RefreshInterval:    models.TimeDuration(23 * time.Hour),
			RegenerateOnRevoke: true,
			SignerSerialNumber: "test-ca-ski",
		},
		LatestCRL: models.LatestCRLMeta{
			Version: bigIntVersion,
		},
	}

	mockCRLService.On("GetCRLSettings", mock.Anything, mock.MatchedBy(func(input services.GetCRLSettingsInput) bool {
		return input.CAID == "test-ca-ski"
	})).Return(vaRole, nil)

	router := setupVARouter(mockOCSPService, mockCRLService)

	req, _ := http.NewRequest("GET", "/va/crl-settings/test-ca-ski", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Verify response can be parsed
	var response map[string]any
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "test-ca-ski", response["ca_id"])
	mockCRLService.AssertExpectations(t)
}

func TestGetCRLSettingsByID_SettingsNotFound(t *testing.T) {
	mockCRLService := new(svcmock.MockVAService)
	mockOCSPService := new(MockOCSPService)

	mockCRLService.On("GetCRLSettings", mock.Anything, mock.MatchedBy(func(input services.GetCRLSettingsInput) bool {
		return input.CAID == "nonexistent-ca-ski"
	})).Return((*models.CRLSettings)(nil), errs.ErrCRLSettingsNotFound)

	router := setupVARouter(mockOCSPService, mockCRLService)

	req, _ := http.NewRequest("GET", "/va/crl-settings/nonexistent-ca-ski", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)

	var response map[string]any
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "CRL settings not found", response["err"])
	mockCRLService.AssertExpectations(t)
}

func TestGetCRLSettingsByID_ValidationError(t *testing.T) {
	mockCRLService := new(svcmock.MockVAService)
	mockOCSPService := new(MockOCSPService)

	mockCRLService.On("GetCRLSettings", mock.Anything, mock.Anything).Return((*models.CRLSettings)(nil), errs.ErrValidateBadRequest)

	router := setupVARouter(mockOCSPService, mockCRLService)

	req, _ := http.NewRequest("GET", "/va/crl-settings/invalid", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]any
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "struct validation error", response["err"])
	mockCRLService.AssertExpectations(t)
}

func TestGetCRLSettingsByID_InternalServerError(t *testing.T) {
	mockCRLService := new(svcmock.MockVAService)
	mockOCSPService := new(MockOCSPService)

	mockCRLService.On("GetCRLSettings", mock.Anything, mock.Anything).Return((*models.CRLSettings)(nil), assert.AnError)

	router := setupVARouter(mockOCSPService, mockCRLService)

	req, _ := http.NewRequest("GET", "/va/crl-settings/test-ca-ski", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	mockCRLService.AssertExpectations(t)
}

func TestUpdateCRLSettings_Success(t *testing.T) {
	mockCRLService := new(svcmock.MockVAService)
	mockOCSPService := new(MockOCSPService)

	bigIntVersion := models.BigInt{Int: big.NewInt(1)}
	updatedRole := &models.CRLSettings{
		CAID: "test-ca-ski",
		Options: models.CRLSettingsOptions{
			Validity:           models.TimeDuration(48 * time.Hour),
			RefreshInterval:    models.TimeDuration(47 * time.Hour),
			RegenerateOnRevoke: false,
			SignerSerialNumber: "test-ca-ski",
		},
		LatestCRL: models.LatestCRLMeta{
			Version: bigIntVersion,
		},
	}

	mockCRLService.On("UpdateCRLSettings", mock.Anything, mock.MatchedBy(func(input services.UpdateCRLSettingsInput) bool {
		return input.CAID == "test-ca-ski"
	})).Return(updatedRole, nil)

	router := setupVARouter(mockOCSPService, mockCRLService)

	updateBody := resources.CRLSettingsUpdate{CRLSettingsOptions: models.CRLSettingsOptions{
		Validity:           models.TimeDuration(172800000000000),
		RefreshInterval:    models.TimeDuration(169200000000000),
		RegenerateOnRevoke: false,
		SignerSerialNumber: "test-ca-ski",
	}}
	bodyBytes, _ := json.Marshal(updateBody)

	req, _ := http.NewRequest("PUT", "/va/crl-settings/test-ca-ski", bytes.NewBuffer(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Verify response can be parsed
	var response map[string]any
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "test-ca-ski", response["ca_id"])

	// Verify CRL options
	crlOptions := response["crl_options"].(map[string]any)
	assert.False(t, crlOptions["regenerate_on_revoke"].(bool))

	mockCRLService.AssertExpectations(t)
}

func TestUpdateCRLSettings_SettingsNotFound(t *testing.T) {
	mockCRLService := new(svcmock.MockVAService)
	mockOCSPService := new(MockOCSPService)

	mockCRLService.On("UpdateCRLSettings", mock.Anything, mock.MatchedBy(func(input services.UpdateCRLSettingsInput) bool {
		return input.CAID == "nonexistent-ca-ski"
	})).Return((*models.CRLSettings)(nil), errs.ErrCRLSettingsNotFound)

	router := setupVARouter(mockOCSPService, mockCRLService)

	updateBody := resources.CRLSettingsUpdate{CRLSettingsOptions: models.CRLSettingsOptions{
		Validity:           models.TimeDuration(172800000000000),
		RefreshInterval:    models.TimeDuration(169200000000000),
		RegenerateOnRevoke: false,
		SignerSerialNumber: "test-ca-ski",
	}}
	bodyBytes, _ := json.Marshal(updateBody)

	req, _ := http.NewRequest("PUT", "/va/crl-settings/nonexistent-ca-ski", bytes.NewBuffer(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)

	var response map[string]any
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "CRL settings not found", response["err"])
	mockCRLService.AssertExpectations(t)
}

func TestUpdateCRLSettings_ValidationError(t *testing.T) {
	mockCRLService := new(svcmock.MockVAService)
	mockOCSPService := new(MockOCSPService)

	mockCRLService.On("UpdateCRLSettings", mock.Anything, mock.Anything).Return((*models.CRLSettings)(nil), errs.ErrValidateBadRequest)

	router := setupVARouter(mockOCSPService, mockCRLService)

	updateBody := resources.CRLSettingsUpdate{CRLSettingsOptions: models.CRLSettingsOptions{
		Validity:           models.TimeDuration(172800000000000),
		RefreshInterval:    models.TimeDuration(169200000000000),
		RegenerateOnRevoke: false,
		SignerSerialNumber: "test-ca-ski",
	}}
	bodyBytes, _ := json.Marshal(updateBody)

	req, _ := http.NewRequest("PUT", "/va/crl-settings/invalid", bytes.NewBuffer(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]any
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "struct validation error", response["err"])
	mockCRLService.AssertExpectations(t)
}

func TestUpdateCRLSettings_InternalServerError(t *testing.T) {
	mockCRLService := new(svcmock.MockVAService)
	mockOCSPService := new(MockOCSPService)

	mockCRLService.On("UpdateCRLSettings", mock.Anything, mock.Anything).Return((*models.CRLSettings)(nil), assert.AnError)

	router := setupVARouter(mockOCSPService, mockCRLService)

	updateBody := resources.CRLSettingsUpdate{CRLSettingsOptions: models.CRLSettingsOptions{
		Validity:           models.TimeDuration(172800000000000),
		RefreshInterval:    models.TimeDuration(169200000000000),
		RegenerateOnRevoke: false,
		SignerSerialNumber: "test-ca-ski",
	}}
	bodyBytes, _ := json.Marshal(updateBody)

	req, _ := http.NewRequest("PUT", "/va/crl-settings/test-ca-ski", bytes.NewBuffer(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	mockCRLService.AssertExpectations(t)
}

func TestUpdateCRLSettings_InvalidJSON(t *testing.T) {
	mockCRLService := new(svcmock.MockVAService)
	mockOCSPService := new(MockOCSPService)

	router := setupVARouter(mockOCSPService, mockCRLService)

	req, _ := http.NewRequest("PUT", "/va/crl-settings/test-ca-ski", bytes.NewBuffer([]byte("invalid-json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCRL_ServesByLegacySKIAndCAIDWithTheSameHandler(t *testing.T) {
	crlService := new(svcmock.MockVAService)
	crl := &x509.RevocationList{Raw: []byte("crl")}
	for _, id := range []string{"018f2d6e-7b3a-7c1e-9a4b-0123456789ab", "3f9a1c"} {
		crlService.On("GetCRL", mock.Anything, mock.MatchedBy(func(in services.GetCRLInput) bool { return in.ID == id })).Return(crl, nil)
	}
	router := setupVARouter(new(MockOCSPService), crlService)

	for _, id := range []string{"018f2d6e-7b3a-7c1e-9a4b-0123456789ab", "3f9a1c"} {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/va/crl/"+id, nil)
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code, id)
	}
	crlService.AssertExpectations(t)
}

// A CRL that was never published is not a server failure.
func TestCRL_NeverPublishedIsNotFound(t *testing.T) {
	crlService := new(svcmock.MockVAService)
	crlService.On("GetCRL", mock.Anything, mock.Anything).Return((*x509.RevocationList)(nil), errs.ErrCRLNotFound)
	router := setupVARouter(new(MockOCSPService), crlService)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/va/crl/some-ca", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestUpdateCRLSettings_NotActiveIsConflict(t *testing.T) {
	crlService := new(svcmock.MockVAService)
	crlService.On("UpdateCRLSettings", mock.Anything, mock.Anything).Return((*models.CRLSettings)(nil), errs.ErrCRLSettingsNotActive)
	router := setupVARouter(new(MockOCSPService), crlService)

	body, _ := json.Marshal(resources.CRLSettingsUpdate{CRLSettingsOptions: models.CRLSettingsOptions{SignerSerialNumber: "sn"}})
	req, _ := http.NewRequest("PUT", "/va/crl-settings/archived-ca", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusConflict, w.Code)
	assert.Contains(t, w.Body.String(), "not active")
}

func TestUpdateCRLSettings_BodyUsesSignerSerialNumber(t *testing.T) {
	crlService := new(svcmock.MockVAService)
	crlService.On("UpdateCRLSettings", mock.Anything, mock.MatchedBy(func(in services.UpdateCRLSettingsInput) bool {
		return in.CAID == "ca-1" && in.Options.SignerSerialNumber == "sn-1" && in.Options.RegenerateOnRevoke
	})).Return(&models.CRLSettings{CAID: "ca-1"}, nil)
	router := setupVARouter(new(MockOCSPService), crlService)

	req, _ := http.NewRequest("PUT", "/va/crl-settings/ca-1", bytes.NewBufferString(`{"signer_serial_number":"sn-1","validity":"1h","refresh_interval":"30m","regenerate_on_revoke":true}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
	crlService.AssertExpectations(t)
}

func TestGetCRLSettingsList_ReturnsPage(t *testing.T) {
	crlService := new(svcmock.MockVAService)
	items := []*models.CRLSettings{{CAID: "a", Status: models.CRLSettingsActive}, {CAID: "b", Status: models.CRLSettingsArchived}}
	crlService.On("GetCRLSettingsList", mock.Anything, mock.Anything).Return(&items, nil)
	router := setupVARouter(new(MockOCSPService), crlService)

	req, _ := http.NewRequest("GET", "/va/crl-settings?filter=status[eq]ACTIVE", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var page resources.GetItemsResponse[models.CRLSettings]
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &page))
	assert.Len(t, page.List, 2)
}
