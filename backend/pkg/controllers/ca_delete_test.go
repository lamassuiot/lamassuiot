package controllers

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/lamassuiot/lamassuiot/v4/sdk"
	"github.com/stretchr/testify/require"
)

type caDeleteTestService struct {
	services.CAService
	err error
}

func (svc *caDeleteTestService) DeleteCA(context.Context, services.DeleteCAInput) error {
	return svc.err
}

// A pending final CRL is a conflict the client can retry, not a server error.
func TestDeleteCAFinalCRLPendingReturnsConflict(t *testing.T) {
	routes := &caHttpRoutes{svc: &caDeleteTestService{err: fmt.Errorf("%w: CA ca-1", errs.ErrCAFinalCRLPending)}}
	router := gin.New()
	router.DELETE("/v1/cas/:id", routes.DeleteCA)
	transport := &importCATransport{handler: router}
	client := sdk.NewHttpCAClient(&http.Client{Transport: transport}, "http://ca.test")

	err := client.DeleteCA(context.Background(), services.DeleteCAInput{CAID: "ca-1"})
	require.Equal(t, http.StatusConflict, transport.status)
	require.ErrorIs(t, err, errs.ErrCAFinalCRLPending)
	require.Contains(t, err.Error(), "CA ca-1", "the SDK keeps the details of the error")
}

// A key that signs the CRLs of another CA is a conflict too, which the SDK tells apart from a pending final CRL.
func TestDeleteCAKeyHeldByCRLSettingsReturnsConflict(t *testing.T) {
	routes := &caHttpRoutes{svc: &caDeleteTestService{err: fmt.Errorf("%w: CA ca-2", errs.ErrCAKeyHeldByCRLSettings)}}
	router := gin.New()
	router.DELETE("/v1/cas/:id", routes.DeleteCA)
	transport := &importCATransport{handler: router}
	client := sdk.NewHttpCAClient(&http.Client{Transport: transport}, "http://ca.test")

	err := client.DeleteCA(context.Background(), services.DeleteCAInput{CAID: "ca-1"})
	require.Equal(t, http.StatusConflict, transport.status)
	require.ErrorIs(t, err, errs.ErrCAKeyHeldByCRLSettings)
	require.Contains(t, err.Error(), "CA ca-2")
}
