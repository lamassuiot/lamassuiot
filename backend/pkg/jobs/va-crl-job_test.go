package jobs

import (
	"context"
	"crypto/x509"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
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
	mockService.On("ReconcileCRLSettings", mock.Anything, mock.Anything).Return(settings[0], nil)

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
	mockService.On("ReconcileCRLSettings", mock.Anything, mock.Anything).Return(settings[0], nil)

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
	mockService.On("ReconcileCRLSettings", mock.Anything, mock.Anything).Return(settings[0], nil)

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
	mockService.On("ReconcileCRLSettings", mock.Anything, mock.Anything).Return(settings[0], nil)

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
	mockService.AssertNotCalled(t, "ReconcileCRLSettings", mock.Anything, mock.Anything)
}

func expiredCRLSettings(caID string) *models.CRLSettings {
	now := time.Now()
	return &models.CRLSettings{
		CAID:   caID,
		Status: models.CRLSettingsActive,
		LatestCRL: models.LatestCRLMeta{
			Version:    models.BigInt{Int: big.NewInt(1)},
			ValidFrom:  now.Add(-time.Hour),
			ValidUntil: now.Add(-time.Minute),
		},
		Options: models.CRLSettingsOptions{Validity: models.TimeDuration(time.Hour)},
	}
}

// The monitor first brings each settings in line with its CA (events may have been lost, or the settings come from the
// migration): settings that turn FINAL are not refreshed.
func TestCRLMonitorReconcilesBeforeRefreshing(t *testing.T) {
	mockService := new(svcmock.MockVAService)
	log := helpers.SetupLogger("debug", "VA", "CRL Monitor")
	job := NewVACrlMonitorJob(log, mockService, time.Second)

	settings := []*models.CRLSettings{expiredCRLSettings("revoked-ca")}
	final := *settings[0]
	final.Status = models.CRLSettingsFinal
	mockService.On("GetCRLSettingsList", mock.Anything, mock.Anything).Return(&settings, nil)
	mockService.On("ReconcileCRLSettings", mock.Anything, reconcileOf("revoked-ca")).Return(&final, nil)

	job.processCRLSettings(context.TODO(), log)

	mockService.AssertExpectations(t)
	mockService.AssertNotCalled(t, "CalculateCRL", mock.Anything, mock.Anything)
}

func TestCRLMonitorReconcileErrorDoesNotStopTheOthers(t *testing.T) {
	mockService := new(svcmock.MockVAService)
	log := helpers.SetupLogger("debug", "VA", "CRL Monitor")
	job := NewVACrlMonitorJob(log, mockService, time.Second)

	settings := []*models.CRLSettings{expiredCRLSettings("failing-ca"), expiredCRLSettings("ok-ca")}
	mockService.On("GetCRLSettingsList", mock.Anything, mock.Anything).Return(&settings, nil)
	mockService.On("ReconcileCRLSettings", mock.Anything, reconcileOf("failing-ca")).Return(nil, errors.New("CA service down"))
	mockService.On("ReconcileCRLSettings", mock.Anything, reconcileOf("ok-ca")).Return(settings[1], nil)
	mockService.On("CalculateCRL", mock.Anything, services.CalculateCRLInput{CAID: "ok-ca"}).Return(&x509.RevocationList{}, nil)

	job.processCRLSettings(context.TODO(), log)

	mockService.AssertExpectations(t)
	mockService.AssertNotCalled(t, "CalculateCRL", mock.Anything, services.CalculateCRLInput{CAID: "failing-ca"})
}

func TestCRLMonitorLeavesRecentRevocationsToTheEvents(t *testing.T) {
	mockService := new(svcmock.MockVAService)
	log := helpers.SetupLogger("debug", "VA", "CRL Monitor")
	job := NewVACrlMonitorJob(log, mockService, time.Second)

	settings := []*models.CRLSettings{expiredCRLSettings("ca")}
	mockService.On("GetCRLSettingsList", mock.Anything, mock.Anything).Return(&settings, nil)
	mockService.On("ReconcileCRLSettings", mock.Anything, mock.MatchedBy(func(in services.ReconcileCRLSettingsInput) bool {
		age := time.Since(in.RevokedBefore)
		return in.CAID == "ca" && age >= reconcileRevocationGrace && age < reconcileRevocationGrace+time.Minute
	})).Return(settings[0], nil)
	mockService.On("CalculateCRL", mock.Anything, mock.Anything).Return(&x509.RevocationList{}, nil)

	job.processCRLSettings(context.TODO(), log)

	mockService.AssertExpectations(t)
}

func reconcileOf(caID string) any {
	return mock.MatchedBy(func(in services.ReconcileCRLSettingsInput) bool { return in.CAID == caID })
}
