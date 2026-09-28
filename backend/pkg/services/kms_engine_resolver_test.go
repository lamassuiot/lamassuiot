package services

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	core "github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/sirupsen/logrus"
)

// derivedTestEngine identifica la instancia derivada para un tenant.
type derivedTestEngine struct {
	cryptoengines.CryptoEngine
	tenantID string
}

func (engine *derivedTestEngine) GetEngineConfig() models.CryptoEngineInfo {
	return models.CryptoEngineInfo{Name: "derived-" + engine.tenantID}
}

type countingDeriver struct {
	builds atomic.Int32
}

func (deriver *countingDeriver) derive(tenantID string) (cryptoengines.CryptoEngine, error) {
	deriver.builds.Add(1)
	return &derivedTestEngine{tenantID: tenantID}, nil
}

func newResolverTestService(t *testing.T, deriver *countingDeriver) *KMSServiceBackend {
	t.Helper()
	svc, err := NewKMSService(KMSServiceBuilder{
		Logger: logrus.New().WithField("test", "kms-engine-resolver"),
		CryptoEngines: map[string]*Engine{
			"global": {
				Default:         true,
				Service:         tenantTestCryptoEngine{provider: models.CryptoEngineInfo{Name: "global"}},
				DeriveForTenant: deriver.derive,
			},
			"engine-a": {
				TenantID: "tenant-a",
				Service:  tenantTestCryptoEngine{provider: models.CryptoEngineInfo{Name: "tenant-a"}},
			},
		},
	})
	if err != nil {
		t.Fatalf("could not build KMS service: %s", err)
	}
	return svc.(*KMSServiceBackend)
}

func TestResolveEngineDerivesOneInstancePerTenant(t *testing.T) {
	deriver := &countingDeriver{}
	svc := newResolverTestService(t, deriver)

	engineA, err := svc.resolveEngine(testKMSValidTenantContext("tenant-a"), "global")
	if err != nil {
		t.Fatalf("unexpected error resolving tenant A: %s", err)
	}
	engineB, err := svc.resolveEngine(testKMSValidTenantContext("tenant-b"), "global")
	if err != nil {
		t.Fatalf("unexpected error resolving tenant B: %s", err)
	}
	if got := engineA.(*derivedTestEngine).tenantID; got != "tenant-a" {
		t.Fatalf("tenant A got the instance of %q", got)
	}
	if got := engineB.(*derivedTestEngine).tenantID; got != "tenant-b" {
		t.Fatalf("tenant B got the instance of %q", got)
	}

	again, err := svc.resolveEngine(testKMSValidTenantContext("tenant-a"), "global")
	if err != nil {
		t.Fatalf("unexpected error resolving tenant A again: %s", err)
	}
	if again != engineA {
		t.Fatal("a repeated request must reuse the tenant instance")
	}
	if builds := deriver.builds.Load(); builds != 2 {
		t.Fatalf("expected one build per tenant (2), got %d", builds)
	}
}

func TestResolveEngineBuildsOnceUnderConcurrency(t *testing.T) {
	deriver := &countingDeriver{}
	svc := newResolverTestService(t, deriver)
	ctx := testKMSValidTenantContext("tenant-a")

	const workers = 50
	results := make([]cryptoengines.CryptoEngine, workers)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			engine, err := svc.resolveEngine(ctx, "global")
			if err != nil {
				t.Errorf("unexpected error: %s", err)
				return
			}
			results[i] = engine
		}(i)
	}
	close(start)
	wg.Wait()

	if builds := deriver.builds.Load(); builds != 1 {
		t.Fatalf("expected a single build for concurrent requests, got %d", builds)
	}
	for i := 1; i < workers; i++ {
		if results[i] != results[0] {
			t.Fatal("concurrent requests got different instances")
		}
	}
}

func TestResolveEngineKeepsTenantBoundAndContextRules(t *testing.T) {
	deriver := &countingDeriver{}
	svc := newResolverTestService(t, deriver)

	engine, err := svc.resolveEngine(testKMSValidTenantContext("tenant-a"), "engine-a")
	if err != nil {
		t.Fatalf("tenant A must use its own engine: %s", err)
	}
	if engine.GetEngineConfig().Name != "tenant-a" {
		t.Fatalf("a tenant-bound engine must be returned unchanged, got %q", engine.GetEngineConfig().Name)
	}
	if _, err := svc.resolveEngine(testKMSValidTenantContext("tenant-b"), "engine-a"); !errors.Is(err, core.ErrTenantResourceAccessDenied) {
		t.Fatalf("expected tenant B to be denied tenant A engine, got %v", err)
	}
	if _, err := svc.resolveEngine(context.Background(), "global"); !errors.Is(err, core.ErrTenantContextRequired) {
		t.Fatalf("expected missing context to be rejected, got %v", err)
	}
	if _, err := svc.resolveEngine(testKMSValidTenantContext("tenant-a"), "missing"); err == nil {
		t.Fatal("expected an unknown engine to be rejected")
	}
	if builds := deriver.builds.Load(); builds != 0 {
		t.Fatalf("no derivation expected, got %d", builds)
	}
}

func TestResolveEngineRejectsUnsafeTenantIDs(t *testing.T) {
	deriver := &countingDeriver{}
	svc := newResolverTestService(t, deriver)

	for _, tenantID := range []string{"..", "tenant/../other", "tenant a", "."} {
		if _, err := svc.resolveEngine(testKMSValidTenantContext(tenantID), "global"); !errors.Is(err, core.ErrTenantResourceAccessDenied) {
			t.Fatalf("expected tenant %q to be rejected with the uniform error, got %v", tenantID, err)
		}
	}
	if builds := deriver.builds.Load(); builds != 0 {
		t.Fatalf("an unsafe tenant ID must never reach the engine builder, got %d builds", builds)
	}
}

func TestResolveEngineDoesNotCacheFailedDerivations(t *testing.T) {
	var calls atomic.Int32
	svc, err := NewKMSService(KMSServiceBuilder{
		Logger: logrus.New().WithField("test", "kms-engine-resolver"),
		CryptoEngines: map[string]*Engine{
			"global": {
				Default: true,
				Service: tenantTestCryptoEngine{},
				DeriveForTenant: func(tenantID string) (cryptoengines.CryptoEngine, error) {
					if calls.Add(1) == 1 {
						return nil, errors.New("storage not ready")
					}
					return &derivedTestEngine{tenantID: tenantID}, nil
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("could not build KMS service: %s", err)
	}
	backend := svc.(*KMSServiceBackend)
	ctx := testKMSValidTenantContext("tenant-a")

	_, err = backend.resolveEngine(ctx, "global")
	if err == nil {
		t.Fatal("expected the first derivation to fail")
	}
	if errors.Is(err, core.ErrTenantResourceAccessDenied) || err.Error() == "storage not ready" {
		t.Fatalf("a build failure must be generic and must not leak its cause, got %v", err)
	}
	if _, err := backend.resolveEngine(ctx, "global"); err != nil {
		t.Fatalf("a failed derivation must be retried, got %v", err)
	}
}

func TestGetCryptoEngineProviderListsConfiguredEnginesAfterDerivation(t *testing.T) {
	deriver := &countingDeriver{}
	svc := newResolverTestService(t, deriver)
	ctx := testKMSValidTenantContext("tenant-a")
	if _, err := svc.resolveEngine(ctx, "global"); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	providers, err := svc.GetCryptoEngineProvider(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	names := map[string]string{}
	for _, provider := range providers {
		names[provider.ID] = provider.Name
	}
	if len(names) != 2 || names["global"] != "global" || names["engine-a"] != "tenant-a" {
		t.Fatalf("expected the configured engines only, got %v", names)
	}
}
