package jobs

import (
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	svcmock "github.com/lamassuiot/lamassuiot/core/v3/pkg/services/mock"
	"github.com/stretchr/testify/mock"
)

func TestCreatePeriodicCRL(t *testing.T) {
	mockService := new(svcmock.MockVAService)

	log := helpers.SetupLogger("debug", "VA", "CRL Monitor")

	// Create a new CryptoMonitor instance with the mock service
	job := NewVACrlMonitorJob(mockService, "@every 10s", log)

	now := time.Now()
	vaRoles := []*models.VARole{
		{
			CAID: "123456",
			LatestCRL: models.LatestCRLMeta{
				Version:    models.BigInt{big.NewInt(1)},
				ValidFrom:  now.Add(-time.Second * 5),
				ValidUntil: now.Add(time.Second * 5),
			},
			CRLOptions: models.VACRLRole{
				Validity:           models.TimeDuration(10 * time.Second),
				KeyIDSigner:        "123456",
				RegenerateOnRevoke: false,
			},
		},
	}

	newCRL := x509.RevocationList{}

	mockService.On("CalculateCRL", mock.Anything, mock.Anything).Return(&newCRL, nil)
	mockService.On("GetVARoles", mock.Anything, mock.Anything).Return(&vaRoles, nil)

	job.Run()

	mockService.AssertCalled(t, "CalculateCRL", mock.Anything, mock.Anything)
}
