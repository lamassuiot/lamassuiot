package controllers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/sdk/v3"
	"github.com/stretchr/testify/require"
)

type duplicateImportCAService struct {
	services.CAService
	input services.ImportCAInput
	calls int
}

func (svc *duplicateImportCAService) ImportCA(_ context.Context, input services.ImportCAInput) (*models.CACertificate, error) {
	svc.input = input
	svc.calls++
	return nil, errs.ErrCAAlreadyExists
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
	svc := &duplicateImportCAService{}
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
}
