package kms

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"

	core "github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

func TestKMSTenantIsolation(t *testing.T) {
	kmsTest, err := StartKMSServiceTestServer(t, false)
	if err != nil {
		t.Fatalf("could not create KMS test server: %s", err)
	}

	tenantA := kmsTenantTestContext("00000000-0000-0000-0000-00000000000a")
	tenantB := kmsTenantTestContext("00000000-0000-0000-0000-00000000000b")
	if _, err := kmsTest.Service.GetKey(context.Background(), services.GetKeyInput{Identifier: "missing-context"}); !errors.Is(err, core.ErrTenantContextRequired) {
		t.Fatalf("expected missing tenant context to be rejected, got %v", err)
	}
	suspendedTenant := core.WithTenantContext(context.Background(), core.TenantContext{
		OrganizationID: "org-kms-isolation",
		TenantID:       "00000000-0000-0000-0000-00000000000a",
		ActorID:        "actor-kms-isolation",
		ActorType:      "test",
		CorrelationID:  "correlation-suspended",
		Source:         "test",
		TenantStatus:   core.TenantSuspended,
		Validated:      true,
	})
	if _, err := kmsTest.Service.GetKey(suspendedTenant, services.GetKeyInput{Identifier: "missing-context"}); !errors.Is(err, core.ErrTenantContextInvalid) {
		t.Fatalf("expected suspended tenant context to be rejected, got %v", err)
	}
	key, err := kmsTest.Service.CreateKey(tenantA, services.CreateKeyInput{
		Name:      "tenant-a-key",
		Algorithm: "RSA",
		Size:      2048,
	})
	if err != nil {
		t.Fatalf("could not create tenant A key: %s", err)
	}

	if _, err := kmsTest.Service.GetKey(tenantB, services.GetKeyInput{Identifier: key.KeyID}); !errors.Is(err, errs.ErrKeyNotFound) {
		t.Fatalf("expected tenant B key lookup to be hidden, got %v", err)
	}
	if _, err := kmsTest.Service.GetKey(tenantB, services.GetKeyInput{Identifier: "unknown-key-id"}); !errors.Is(err, errs.ErrKeyNotFound) {
		t.Fatalf("expected unknown key lookup to use the same not-found error, got %v", err)
	}
	if _, err := kmsTest.Service.UpdateKeyName(tenantB, services.UpdateKeyNameInput{ID: key.KeyID, Name: "cross-tenant-update"}); !errors.Is(err, errs.ErrKeyNotFound) {
		t.Fatalf("expected tenant B key update to be rejected, got %v", err)
	}
	if err := kmsTest.Service.DeleteKeyByID(tenantB, services.GetKeyInput{Identifier: key.KeyID}); !errors.Is(err, errs.ErrKeyNotFound) {
		t.Fatalf("expected tenant B key deletion to be rejected, got %v", err)
	}
}

func TestKMSImportedKeyTenantIsolation(t *testing.T) {
	kmsTest, err := StartKMSServiceTestServer(t, false)
	if err != nil {
		t.Fatalf("could not create KMS test server: %s", err)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("could not generate imported key: %s", err)
	}

	tenantA := kmsTenantTestContext("00000000-0000-0000-0000-00000000000a")
	tenantB := kmsTenantTestContext("00000000-0000-0000-0000-00000000000b")
	key, err := kmsTest.Service.ImportKey(tenantA, services.ImportKeyInput{
		PrivateKey: privateKey,
		Name:       "tenant-a-imported-key",
	})
	if err != nil {
		t.Fatalf("could not import tenant A key: %s", err)
	}

	if _, err := kmsTest.Service.GetKey(tenantB, services.GetKeyInput{Identifier: key.KeyID}); !errors.Is(err, errs.ErrKeyNotFound) {
		t.Fatalf("expected tenant B imported key lookup to be hidden, got %v", err)
	}
}

func kmsTenantTestContext(tenantID string) context.Context {
	return core.WithTenantContext(context.Background(), core.TenantContext{
		OrganizationID: "org-kms-isolation",
		TenantID:       tenantID,
		ActorID:        "actor-kms-isolation",
		ActorType:      "test",
		CorrelationID:  "correlation-" + tenantID,
		Source:         "test",
		TenantStatus:   core.TenantActive,
		Validated:      true,
	})
}
