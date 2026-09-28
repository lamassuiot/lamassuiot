package services

import (
	"context"
	"testing"

	core "github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"gocloud.dev/blob/memblob"
)

func TestTenantCRLObjectKeyIsolatedByTenant(t *testing.T) {
	contextFor := func(tenantID string) context.Context {
		return core.WithTenantContext(context.Background(), core.TenantContext{
			OrganizationID: "org-1",
			TenantID:       tenantID,
			ActorID:        "test",
			ActorType:      "system",
			CorrelationID:  "crl-test-" + tenantID,
			Source:         "crl-test",
			TenantStatus:   core.TenantActive,
			Validated:      true,
		})
	}

	keyA, err := tenantCRLObjectKey(contextFor("tenant-a"), "ca-ski", "7")
	assert.NoError(t, err)
	keyB, err := tenantCRLObjectKey(contextFor("tenant-b"), "ca-ski", "7")
	assert.NoError(t, err)
	assert.NotEqual(t, keyA, keyB)
	assert.Equal(t, "pki/va/crl/tenants/tenant-a/ca-ski/7.crl", keyA)

	_, err = tenantCRLObjectKey(context.Background(), "ca-ski", "7")
	assert.Error(t, err)
}

func TestReadCRLObjectFallsBackToLegacyKeyOnlyForDefaultTenant(t *testing.T) {
	ctx := context.Background()
	bucket := memblob.OpenBucket(nil)
	defer bucket.Close()
	legacy := []byte("legacy-crl")
	assert.NoError(t, bucket.WriteAll(ctx, "pki/va/crl/ca-ski/3.crl", legacy, nil))
	logger := logrus.NewEntry(logrus.New())
	contextFor := func(tenantID string) context.Context {
		return core.WithTenantContext(ctx, core.TenantContext{
			OrganizationID: "org-1", TenantID: tenantID, ActorID: "test", ActorType: "system",
			CorrelationID: "crl-legacy", Source: "crl-test", TenantStatus: core.TenantActive, Validated: true,
		})
	}

	_, err := readCRLObject(contextFor("tenant-a"), logger, bucket, "ca-ski", "3")
	assert.Error(t, err, "other tenants never read legacy objects")

	data, err := readCRLObject(contextFor(models.DefaultTenantID), logger, bucket, "ca-ski", "3")
	assert.NoError(t, err)
	assert.Equal(t, legacy, data)
	copied, err := bucket.ReadAll(ctx, "pki/va/crl/tenants/"+models.DefaultTenantID+"/ca-ski/3.crl")
	assert.NoError(t, err, "the legacy CRL is copied to the tenant key")
	assert.Equal(t, legacy, copied)

	_, err = readCRLObject(contextFor(models.DefaultTenantID), logger, bucket, "ca-ski", "4")
	assert.Error(t, err, "a CRL missing in both keys is still an error")
}
