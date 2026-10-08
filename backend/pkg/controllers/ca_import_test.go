package controllers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/sdk/v3"
	"github.com/stretchr/testify/require"
)

type caCreationTestService struct {
	services.CAService
	input services.ImportCAInput
	calls int
	err   error
}

func (svc *caCreationTestService) ImportCA(_ context.Context, input services.ImportCAInput) (*models.CACertificate, error) {
	svc.input = input
	svc.calls++
	if svc.err != nil {
		return nil, svc.err
	}
	return nil, errs.ErrCAAlreadyExists
}

func (svc *caCreationTestService) CreateCA(context.Context, services.CreateCAInput) (*models.CACertificate, error) {
	svc.calls++
	return nil, svc.err
}

// Route SDK requests through the real controller without opening a socket.
type importCATransport struct {
	handler http.Handler
	status  int
}

func (transport *importCATransport) RoundTrip(req *http.Request) (*http.Response, error) {
	recorder := httptest.NewRecorder()
	transport.handler.ServeHTTP(recorder, req)
	transport.status = recorder.Code
	return recorder.Result(), nil
}

func TestImportCADuplicateIDReturnsConflict(t *testing.T) {
	for _, wrapped := range []bool{false, true} {
		t.Run(fmt.Sprintf("wrapped=%t", wrapped), func(t *testing.T) {
			serviceErr := errs.ErrCAAlreadyExists
			if wrapped {
				serviceErr = fmt.Errorf("CA import: %w", serviceErr)
			}
			svc := &caCreationTestService{err: serviceErr}
			routes := &caHttpRoutes{svc: svc}
			router := gin.New()
			router.POST("/v1/cas/import", routes.ImportCA)
			transport := &importCATransport{handler: router}
			client := sdk.NewHttpCAClient(&http.Client{Transport: transport}, "http://ca.test")

			ca, err := client.ImportCA(context.Background(), services.ImportCAInput{ID: "existing-ca"})
			require.Equal(t, http.StatusConflict, transport.status)
			require.ErrorIs(t, err, errs.ErrCAAlreadyExists)
			require.Nil(t, ca)
			require.Equal(t, 1, svc.calls)
			require.Equal(t, "existing-ca", svc.input.ID)
		})
	}
}

func TestCACreationErrorResponses(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		status int
	}{
		{name: "duplicate ID", err: errs.ErrCAAlreadyExists, status: http.StatusConflict},
		{name: "wrapped duplicate ID", err: fmt.Errorf("CA operation: %w", errs.ErrCAAlreadyExists), status: http.StatusConflict},
		{name: "missing profile", err: errs.ErrIssuanceProfileNotFound, status: http.StatusNotFound},
		{name: "invalid request", err: errs.ErrValidateBadRequest, status: http.StatusBadRequest},
		{name: "invalid CA type", err: errs.ErrCAType, status: http.StatusBadRequest},
		{name: "invalid expiration", err: errs.ErrCAIssuanceExpiration, status: http.StatusBadRequest},
		{name: "incompatible validity", err: errs.ErrCAIncompatibleValidity, status: http.StatusBadRequest},
		{name: "invalid key and certificate", err: errs.ErrCAValidCertAndPrivKey, status: http.StatusBadRequest},
		{name: "storage failure", err: errors.New("CA storage unavailable"), status: http.StatusInternalServerError},
	} {
		for _, importing := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/import=%t", tc.name, importing), func(t *testing.T) {
				svc := &caCreationTestService{err: tc.err}
				routes := NewCAHttpRoutes(svc)
				router := gin.New()
				handler := routes.CreateCA
				status := tc.status
				if importing {
					handler = routes.ImportCA
				} else if errors.Is(tc.err, errs.ErrCAValidCertAndPrivKey) {
					// This error is specific to importing a certificate/key pair.
					status = http.StatusInternalServerError
				}
				router.POST("/cas", handler)
				request := httptest.NewRequest(http.MethodPost, "/cas", strings.NewReader(`{"id":"test-ca"}`))
				request.Header.Set("Content-Type", "application/json")
				response := httptest.NewRecorder()
				router.ServeHTTP(response, request)
				require.Equal(t, status, response.Code)
				require.Equal(t, 1, svc.calls)
				var body map[string]string
				require.NoError(t, json.Unmarshal(response.Body.Bytes(), &body))
				message := tc.err.Error()
				if errors.Is(tc.err, errs.ErrCAAlreadyExists) {
					message = errs.ErrCAAlreadyExists.Error()
				}
				require.Equal(t, message, body["err"])
			})
		}
	}
}
