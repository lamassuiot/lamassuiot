package catokms

import (
	"context"
	"errors"
	"testing"
	"time"

	core "github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
)

// tenantScopedCAStorage behaves like the PostgreSQL repositories: it refuses
// queries without a TenantContext and only returns the tenant's rows.
type tenantScopedCAStorage struct {
	mockCACertStorage
	queriedTenants []string
}

func (m *tenantScopedCAStorage) SelectByType(ctx context.Context, caType models.CertificateType, req storage.StorageListRequest[models.CACertificate]) (string, error) {
	tenantContext, err := core.RequireTenantContext(ctx)
	if err != nil {
		return "", err
	}
	m.queriedTenants = append(m.queriedTenants, tenantContext.TenantID)
	for _, ca := range m.certs {
		if ca.TenantID == tenantContext.TenantID && ca.Certificate.Type == caType {
			req.ApplyFunc(ca)
		}
	}
	return "", nil
}

type activeTenantsStub struct {
	tenants []models.Tenant
	err     error
}

func (stub activeTenantsStub) ListActiveTenants(context.Context) ([]models.Tenant, error) {
	return stub.tenants, stub.err
}

func TestMigrateAllTenantsMigratesEachTenantUnderItsOwnScope(t *testing.T) {
	caA := newRSACACert(t, "ca-a", "serial-a", "engine-a", models.CertificateTypeManaged, 2048, "CA A", time.Now())
	caA.TenantID = "tenant-a"
	caB := newRSACACert(t, "ca-b", "serial-b", "engine-b", models.CertificateTypeManaged, 2048, "CA B", time.Now())
	caB.TenantID = "tenant-b"
	caStorage := &tenantScopedCAStorage{mockCACertStorage: mockCACertStorage{certs: []models.CACertificate{caA, caB}}}
	kms := newMockKMSStorage()

	result, err := MigrateAllTenants(context.Background(), silentLogger(), activeTenantsStub{tenants: []models.Tenant{
		{ID: "tenant-a", OrganizationID: "org", Status: models.TenantActive},
		{ID: "tenant-b", OrganizationID: "org", Status: models.TenantActive},
	}}, caStorage, kms, false)
	if err != nil {
		t.Fatalf("migration failed: %s", err)
	}
	if result.Inserted != 2 || len(kms.inserted) != 2 {
		t.Fatalf("expected one key per tenant, got result=%+v inserted=%d", result, len(kms.inserted))
	}
	owners := map[string]string{}
	for _, key := range kms.inserted {
		owners[key.Name] = key.TenantID
	}
	if owners["CA A"] != "tenant-a" || owners["CA B"] != "tenant-b" {
		t.Fatalf("keys must keep their CA's tenant, got %v", owners)
	}
	if len(caStorage.queriedTenants) == 0 {
		t.Fatal("the CA storage was never queried with a tenant scope")
	}
}

func TestMigrateAllTenantsStopsWhenTenantsCannotBeListed(t *testing.T) {
	_, err := MigrateAllTenants(context.Background(), silentLogger(), activeTenantsStub{err: errors.New("control plane down")},
		&tenantScopedCAStorage{}, newMockKMSStorage(), false)
	if err == nil {
		t.Fatal("expected an error when active tenants cannot be listed")
	}
}
