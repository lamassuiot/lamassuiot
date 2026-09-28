package alerts

import (
	"crypto/x509"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/assemblers/tests"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

// TestTenantEventsPropagateEndToEnd drives CA → event bus → Alerts for two
// tenants at the same time: each tenant's CA creation reaches the Alerts
// store under that tenant only, with the tenant and correlation of the
// originating request.
func TestTenantEventsPropagateEndToEnd(t *testing.T) {
	tenants := map[string]string{
		"00000000-0000-0000-0000-00000000000a": "correlation-tenant-a",
		"00000000-0000-0000-0000-00000000000b": "correlation-tenant-b",
	}
	serverTest, err := tests.TestServiceBuilder{}.WithDatabase("ca", "alerts", "kms").
		WithService(tests.CA, tests.ALERTS).WithEventBus().
		WithTenantIDs("00000000-0000-0000-0000-00000000000a", "00000000-0000-0000-0000-00000000000b").Build(t)
	if err != nil {
		t.Fatalf("could not create test server: %s", err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, len(tenants))
	for tenantID, correlationID := range tenants {
		wg.Add(1)
		go func(tenantID, correlationID string) {
			defer wg.Done()
			ctx := tests.TenantContextFor(tenantID, correlationID)
			profile, err := serverTest.CA.Service.CreateIssuanceProfile(ctx, services.CreateIssuanceProfileInput{
				Profile: models.IssuanceProfile{Validity: models.Validity{Type: models.Duration, Duration: models.TimeDuration(12 * time.Hour)}},
			})
			if err != nil {
				errs <- fmt.Errorf("tenant %s profile: %w", tenantID, err)
				return
			}
			_, err = serverTest.CA.Service.CreateCA(ctx, services.CreateCAInput{
				ID:           "event-ca-" + tenantID,
				KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.ECDSA), Bits: 256},
				Subject:      models.Subject{CommonName: "Event CA"},
				CAExpiration: models.Validity{Type: models.Duration, Duration: models.TimeDuration(24 * time.Hour)},
				ProfileID:    profile.ID,
			})
			if err != nil {
				errs <- fmt.Errorf("tenant %s CA: %w", tenantID, err)
			}
		}(tenantID, correlationID)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}

	for tenantID, correlationID := range tenants {
		ctx := tests.TenantContextFor(tenantID)
		err := tests.SleepRetry(15, 2*time.Second, func() error {
			events, err := serverTest.Alerts.Service.GetLatestEventsPerEventType(ctx, &services.GetLatestEventsPerEventTypeInput{})
			if err != nil {
				return err
			}
			for _, event := range events {
				if event.TenantID != tenantID {
					return fmt.Errorf("tenant %s sees an event stored for tenant %s", tenantID, event.TenantID)
				}
				if event.EventType != models.EventCreateCAKey {
					continue
				}
				gotTenant, _ := event.Event.Extensions()["tenantid"].(string)
				gotCorrelation, _ := event.Event.Extensions()["correlationid"].(string)
				if gotTenant != tenantID || gotCorrelation != correlationID {
					return fmt.Errorf("ca.create for tenant %s carries tenant=%q correlation=%q", tenantID, gotTenant, gotCorrelation)
				}
				if event.TotalSeen != 1 {
					return fmt.Errorf("tenant %s counted %d ca.create events, want 1 (no cross-tenant mixing)", tenantID, event.TotalSeen)
				}
				return nil
			}
			return fmt.Errorf("tenant %s has not received its ca.create event yet", tenantID)
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
