package controllers

import (
	"context"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/lamassuiot/lamassuiot/v4/sdk"
	"github.com/stretchr/testify/require"
)

type rejectCACertificateService struct {
	services.CAService
	input services.CreateCertificateInput
}

func (svc *rejectCACertificateService) CreateCertificate(_ context.Context, input services.CreateCertificateInput) (*models.Certificate, error) {
	svc.input = input
	return nil, errs.ErrSignAsCANotAllowed
}

func TestCreateCertificateSignAsCAReturnsBadRequest(t *testing.T) {
	svc := &rejectCACertificateService{}
	router := gin.New()
	router.POST("/v1/certificates", (&caHttpRoutes{svc: svc}).CreateCertificate)
	transport := &importCATransport{handler: router}
	client := sdk.NewHttpCAClient(&http.Client{Transport: transport}, "http://ca.test")

	cert, err := client.CreateCertificate(context.Background(), services.CreateCertificateInput{
		CAID: "ca-id", IssuanceProfile: &models.IssuanceProfile{SignAsCA: true},
	})

	require.Equal(t, http.StatusBadRequest, transport.status)
	require.ErrorIs(t, err, errs.ErrSignAsCANotAllowed)
	require.Nil(t, cert)
	require.NotNil(t, svc.input.IssuanceProfile)
	require.True(t, svc.input.IssuanceProfile.SignAsCA)
}
