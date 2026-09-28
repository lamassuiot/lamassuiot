package va

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	core "github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

func vaTenantTestContext(tenantID string) context.Context {
	return core.WithTenantContext(context.Background(), core.TenantContext{
		OrganizationID: "org-va-isolation",
		TenantID:       tenantID,
		ActorID:        "actor-va-isolation",
		ActorType:      "test",
		CorrelationID:  "correlation-" + tenantID,
		Source:         "test",
		TenantStatus:   core.TenantActive,
		Validated:      true,
	})
}

func TestVATenantIsolation(t *testing.T) {
	serverTest, err := StartVAServiceTestServer(t)
	if err != nil {
		t.Fatalf("could not create VA test server: %s", err)
	}

	tenantA := vaTenantTestContext("00000000-0000-0000-0000-00000000000a")
	tenantB := vaTenantTestContext("00000000-0000-0000-0000-00000000000b")
	if _, err := serverTest.VA.CRLService.GetVARole(context.Background(), services.GetVARoleInput{CASubjectKeyID: "missing-context"}); !errors.Is(err, core.ErrTenantContextRequired) {
		t.Fatalf("expected missing tenant context to be rejected, got %v", err)
	}
	suspendedTenant := core.WithTenantContext(context.Background(), core.TenantContext{
		OrganizationID: "org-va-isolation",
		TenantID:       "00000000-0000-0000-0000-00000000000a",
		ActorID:        "actor-va-isolation",
		ActorType:      "test",
		CorrelationID:  "correlation-suspended",
		Source:         "test",
		TenantStatus:   core.TenantSuspended,
		Validated:      true,
	})
	if _, err := serverTest.VA.CRLService.GetVARole(suspendedTenant, services.GetVARoleInput{CASubjectKeyID: "missing-context"}); !errors.Is(err, core.ErrTenantContextInvalid) {
		t.Fatalf("expected suspended tenant context to be rejected, got %v", err)
	}

	profile, err := serverTest.CA.Service.CreateIssuanceProfile(tenantA, services.CreateIssuanceProfileInput{
		Profile: models.IssuanceProfile{
			Name:     "tenant-a-va-profile",
			SignAsCA: true,
			Validity: models.Validity{Type: models.Duration, Duration: models.TimeDuration(24 * time.Hour)},
		},
	})
	if err != nil {
		t.Fatalf("could not create tenant A profile: %s", err)
	}

	ca, err := serverTest.CA.Service.CreateCA(tenantA, services.CreateCAInput{
		KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
		Subject:      models.Subject{CommonName: "tenant-a-va-ca"},
		CAExpiration: models.Validity{Type: models.Duration, Duration: models.TimeDuration(24 * time.Hour)},
		ProfileID:    profile.ID,
	})
	if err != nil {
		t.Fatalf("could not create tenant A CA: %s", err)
	}

	caSKI := hex.EncodeToString(ca.Certificate.Certificate.SubjectKeyId)
	role, err := serverTest.VA.CRLService.InitCRLRole(tenantA, caSKI)
	if err != nil {
		t.Fatalf("could not initialize tenant A VA role: %s", err)
	}

	if _, err := serverTest.VA.CRLService.GetVARole(tenantB, services.GetVARoleInput{CASubjectKeyID: role.CASubjectKeyID}); !errors.Is(err, errs.ErrVARoleNotFound) {
		t.Fatalf("expected tenant B VA role lookup to be hidden, got %v", err)
	}
	if _, err := serverTest.VA.CRLService.GetVARole(tenantB, services.GetVARoleInput{CASubjectKeyID: "unknown-ca-ski"}); !errors.Is(err, errs.ErrVARoleNotFound) {
		t.Fatalf("expected unknown VA role lookup to use the same not-found error, got %v", err)
	}
	if _, err := serverTest.VA.CRLService.UpdateVARole(tenantB, services.UpdateVARoleInput{
		CASubjectKeyID: role.CASubjectKeyID,
		CRLRole:        role.CRLOptions,
	}); !errors.Is(err, errs.ErrVARoleNotFound) {
		t.Fatalf("expected tenant B VA role update to be rejected, got %v", err)
	}
}
