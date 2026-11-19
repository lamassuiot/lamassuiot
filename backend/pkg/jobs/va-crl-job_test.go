package jobs

import (
	"context"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	svcmock "github.com/lamassuiot/lamassuiot/v4/core/pkg/services/mock"
	"github.com/stretchr/testify/mock"
)

func TestCreatePeriodicCRLExpired(t *testing.T) {
	mockService := new(svcmock.MockVAService)

	log := helpers.SetupLogger("debug", "VA", "CRL Monitor")

	// Create a new CryptoMonitor instance with the mock service
	job := NewVACrlMonitorJob(log, mockService, time.Duration(time.Second*1))

	now := time.Now()
	settings := []*models.CRLSettings{
		{
			CAID:   "123456",
			Status: models.CRLSettingsActive,
			LatestCRL: models.LatestCRLMeta{
				Version:    models.BigInt{Int: big.NewInt(1)},
				ValidFrom:  now.Add(-time.Second * 5),
				ValidUntil: now.Add(-time.Second * 1),
			},
			Options: models.CRLSettingsOptions{
				Validity:           models.TimeDuration(10 * time.Second),
				SignerSerialNumber: "123456",
				RegenerateOnRevoke: false,
			},
		},
	}

	newCRL := x509.RevocationList{}

	mockService.On("CalculateCRL", mock.Anything, mock.Anything).Return(&newCRL, nil)
	mockService.On("GetCRLSettingsList", mock.Anything, mock.Anything).Return(&settings, nil)

	job.processCRLSettings(context.TODO(), log)

	mockService.AssertCalled(t, "CalculateCRL", mock.Anything, mock.Anything)
}

func TestCreatePeriodicCRLValid(t *testing.T) {
	mockService := new(svcmock.MockVAService)

	log := helpers.SetupLogger("debug", "VA", "CRL Monitor")

	// Create a new CryptoMonitor instance with the mock service
	job := NewVACrlMonitorJob(log, mockService, time.Duration(time.Second*1))

	now := time.Now()
	settings := []*models.CRLSettings{
		{
			CAID:   "123456",
			Status: models.CRLSettingsActive,
			LatestCRL: models.LatestCRLMeta{
				Version:    models.BigInt{Int: big.NewInt(1)},
				ValidFrom:  now.Add(-time.Second * 5),
				ValidUntil: now.Add(time.Second * 10000),
			},
			Options: models.CRLSettingsOptions{
				Validity:           models.TimeDuration(10 * time.Second),
				SignerSerialNumber: "123456",
				RegenerateOnRevoke: false,
			},
		},
	}

	newCRL := x509.RevocationList{}

	mockService.On("CalculateCRL", mock.Anything, mock.Anything).Return(&newCRL, nil)
	mockService.On("GetCRLSettingsList", mock.Anything, mock.Anything).Return(&settings, nil)

	job.processCRLSettings(context.TODO(), log)

	mockService.AssertNotCalled(t, "CalculateCRL", mock.Anything, mock.Anything)
}

func TestCreatePeriodicCRLRefreshIntervalElapsed(t *testing.T) {
	mockService := new(svcmock.MockVAService)

	log := helpers.SetupLogger("debug", "VA", "CRL Monitor")

	job := NewVACrlMonitorJob(log, mockService, time.Duration(time.Second*1))

	now := time.Now()
	settings := []*models.CRLSettings{
		{
			CAID:   "123456",
			Status: models.CRLSettingsActive,
			LatestCRL: models.LatestCRLMeta{
				Version:    models.BigInt{Int: big.NewInt(1)},
				ValidFrom:  now.Add(-time.Hour * 2),
				ValidUntil: now.Add(time.Hour * 24 * 7),
			},
			Options: models.CRLSettingsOptions{
				Validity:           models.TimeDuration(24 * 7 * time.Hour),
				RefreshInterval:    models.TimeDuration(time.Hour),
				SignerSerialNumber: "123456",
				RegenerateOnRevoke: false,
			},
		},
	}

	newCRL := x509.RevocationList{}

	mockService.On("CalculateCRL", mock.Anything, mock.Anything).Return(&newCRL, nil)
	mockService.On("GetCRLSettingsList", mock.Anything, mock.Anything).Return(&settings, nil)

	job.processCRLSettings(context.TODO(), log)

	mockService.AssertCalled(t, "CalculateCRL", mock.Anything, mock.Anything)
}

func TestCreatePeriodicCRLRefreshIntervalNotElapsed(t *testing.T) {
	mockService := new(svcmock.MockVAService)

	log := helpers.SetupLogger("debug", "VA", "CRL Monitor")

	job := NewVACrlMonitorJob(log, mockService, time.Duration(time.Second*1))

	now := time.Now()
	settings := []*models.CRLSettings{
		{
			CAID:   "123456",
			Status: models.CRLSettingsActive,
			LatestCRL: models.LatestCRLMeta{
				Version:    models.BigInt{Int: big.NewInt(1)},
				ValidFrom:  now.Add(-time.Minute * 30),
				ValidUntil: now.Add(time.Hour * 24 * 7),
			},
			Options: models.CRLSettingsOptions{
				Validity:           models.TimeDuration(24 * 7 * time.Hour),
				RefreshInterval:    models.TimeDuration(time.Hour),
				SignerSerialNumber: "123456",
				RegenerateOnRevoke: false,
			},
		},
	}

	newCRL := x509.RevocationList{}

	mockService.On("CalculateCRL", mock.Anything, mock.Anything).Return(&newCRL, nil)
	mockService.On("GetCRLSettingsList", mock.Anything, mock.Anything).Return(&settings, nil)

	job.processCRLSettings(context.TODO(), log)

	mockService.AssertNotCalled(t, "CalculateCRL", mock.Anything, mock.Anything)
}

func TestCreatePeriodicCRLSkipsNonActiveSettings(t *testing.T) {
	mockService := new(svcmock.MockVAService)
	log := helpers.SetupLogger("debug", "VA", "CRL Monitor")
	job := NewVACrlMonitorJob(log, mockService, time.Second)

	now := time.Now()
	settings := []*models.CRLSettings{{
		CAID:   "archived",
		Status: models.CRLSettingsArchived,
		LatestCRL: models.LatestCRLMeta{
			Version:    models.BigInt{Int: big.NewInt(1)},
			ValidFrom:  now.Add(-time.Hour * 24 * 30),
			ValidUntil: now.Add(-time.Hour * 24),
		},
		Options: models.CRLSettingsOptions{RefreshInterval: models.TimeDuration(time.Hour)},
	}}

	mockService.On("CalculateCRL", mock.Anything, mock.Anything).Return(&x509.RevocationList{}, nil)
	mockService.On("GetCRLSettingsList", mock.Anything, mock.Anything).Return(&settings, nil)

	job.processCRLSettings(context.TODO(), log)

	mockService.AssertNotCalled(t, "CalculateCRL", mock.Anything, mock.Anything)
}
