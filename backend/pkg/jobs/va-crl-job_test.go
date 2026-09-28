package jobs

import (
	"context"
	"crypto/x509"
	"math/big"
	"sync"
	"testing"
	"time"

	core "github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	svcmock "github.com/lamassuiot/lamassuiot/core/v3/pkg/services/mock"
	"github.com/stretchr/testify/mock"
)

type activeTenantListerStub struct {
	tenants []models.Tenant
	err     error
}

func (stub activeTenantListerStub) ListActiveTenants(context.Context) ([]models.Tenant, error) {
	return stub.tenants, stub.err
}

func TestVACrlMonitorUsesTenantContext(t *testing.T) {
	mockService := new(svcmock.MockVAService)
	logger := helpers.SetupLogger("error", "VA", "CRL Monitor")
	job := NewVACrlMonitorJob(logger, mockService, time.Minute)
	job.SetTenantLister(activeTenantListerStub{tenants: []models.Tenant{
		{ID: "tenant-a", OrganizationID: "org-a", Status: models.TenantActive},
		{ID: "tenant-b", OrganizationID: "org-b", Status: models.TenantActive},
	}})

	var mu sync.Mutex
	seenGet := map[string]bool{}
	seenCalculate := map[string]bool{}
	expiredRoles := []*models.VARole{{
		CASubjectKeyID: "shared-ski",
		LatestCRL: models.LatestCRLMeta{
			Version:    models.BigInt{Int: big.NewInt(1)},
			ValidUntil: time.Now().Add(-time.Second),
		},
	}}
	mockService.On("GetVARoles", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			ctx := args.Get(0).(context.Context)
			tenantContext, err := core.RequireTenantContext(ctx)
			if err != nil {
				t.Errorf("GetVARoles received invalid tenant context: %s", err)
				return
			}
			mu.Lock()
			seenGet[tenantContext.TenantID] = true
			mu.Unlock()
		}).
		Return(&expiredRoles, nil)
	mockService.On("CalculateCRL", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			ctx := args.Get(0).(context.Context)
			tenantContext, err := core.RequireTenantContext(ctx)
			if err != nil {
				t.Errorf("CalculateCRL received invalid tenant context: %s", err)
				return
			}
			mu.Lock()
			seenCalculate[tenantContext.TenantID] = true
			mu.Unlock()
		}).
		Return(&x509.RevocationList{}, nil)

	job.Run()

	mockService.AssertExpectations(t)
	if len(seenGet) != 2 || len(seenCalculate) != 2 {
		t.Fatalf("expected scoped CRL work for both active tenants; GetVARoles=%v CalculateCRL=%v", seenGet, seenCalculate)
	}
}

func TestCreatePeriodicCRLExpired(t *testing.T) {
	mockService := new(svcmock.MockVAService)

	log := helpers.SetupLogger("debug", "VA", "CRL Monitor")

	// Create a new CryptoMonitor instance with the mock service
	job := NewVACrlMonitorJob(log, mockService, time.Duration(time.Second*1))

	now := time.Now()
	vaRoles := []*models.VARole{
		{
			CASubjectKeyID: "123456",
			LatestCRL: models.LatestCRLMeta{
				Version:    models.BigInt{Int: big.NewInt(1)},
				ValidFrom:  now.Add(-time.Second * 5),
				ValidUntil: now.Add(-time.Second * 1),
			},
			CRLOptions: models.VACRLRole{
				Validity:           models.TimeDuration(10 * time.Second),
				SubjectKeyIDSigner: "123456",
				RegenerateOnRevoke: false,
			},
		},
	}

	newCRL := x509.RevocationList{}

	mockService.On("CalculateCRL", mock.Anything, mock.Anything).Return(&newCRL, nil)
	mockService.On("GetVARoles", mock.Anything, mock.Anything).Return(&vaRoles, nil)

	job.processVARoles(context.TODO(), log)

	mockService.AssertCalled(t, "CalculateCRL", mock.Anything, mock.Anything)
}

func TestCreatePeriodicCRLValid(t *testing.T) {
	mockService := new(svcmock.MockVAService)

	log := helpers.SetupLogger("debug", "VA", "CRL Monitor")

	// Create a new CryptoMonitor instance with the mock service
	job := NewVACrlMonitorJob(log, mockService, time.Duration(time.Second*1))

	now := time.Now()
	vaRoles := []*models.VARole{
		{
			CASubjectKeyID: "123456",
			LatestCRL: models.LatestCRLMeta{
				Version:    models.BigInt{Int: big.NewInt(1)},
				ValidFrom:  now.Add(-time.Second * 5),
				ValidUntil: now.Add(time.Second * 10000),
			},
			CRLOptions: models.VACRLRole{
				Validity:           models.TimeDuration(10 * time.Second),
				SubjectKeyIDSigner: "123456",
				RegenerateOnRevoke: false,
			},
		},
	}

	newCRL := x509.RevocationList{}

	mockService.On("CalculateCRL", mock.Anything, mock.Anything).Return(&newCRL, nil)
	mockService.On("GetVARoles", mock.Anything, mock.Anything).Return(&vaRoles, nil)

	job.processVARoles(context.TODO(), log)

	mockService.AssertNotCalled(t, "CalculateCRL", mock.Anything, mock.Anything)
}
