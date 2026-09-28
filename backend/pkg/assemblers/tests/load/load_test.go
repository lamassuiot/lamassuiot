//go:build load

// Package load runs the multi-tenant load and chaos campaign L-01..L-03 of
// spec 008 against in-process CA and KMS services backed by PostgreSQL.
//
//	CGO_ENABLED=1 go test -tags load ./pkg/assemblers/tests/load -run TestLoadCampaign -timeout 60m -v
//
// Tunables (environment): LOAD_TENANTS (4), LOAD_DURATION (30s),
// LOAD_RPS (10 per tenant), LOAD_NOISY_FACTOR (8), LOAD_REPORT (JSON file).
package load

import (
	"context"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http/httptest"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/assemblers/tests"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3"
	pgconfig "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3/config"
	sdk "github.com/lamassuiot/lamassuiot/sdk/v3"
	"github.com/sirupsen/logrus"
)

// Approved baseline (spec 002, 327.4).
const (
	apiP95Limit   = 500 * time.Millisecond
	pkiP95Limit   = 2 * time.Second
	errorRateMax  = 0.01
	opRead        = "api.read"
	opSign        = "pki.sign"
	opCrossTenant = "isolation.probe"
)

type sample struct {
	op      string
	at      time.Time
	latency time.Duration
	err     error
}

type tenantLoad struct {
	id    string
	ctx   context.Context
	caID  string
	csrs  []*x509.CertificateRequest
	certs []string
	mu    sync.Mutex
}

type opStats struct {
	Count      int     `json:"count"`
	Errors     int     `json:"errors"`
	Throttled  int     `json:"throttled"`
	P50Ms      float64 `json:"p50_ms"`
	P95Ms      float64 `json:"p95_ms"`
	P99Ms      float64 `json:"p99_ms"`
	ErrorRate  float64 `json:"error_rate"`
	Violations int     `json:"isolation_violations"`
	// ProbeUnexpected counts cross-tenant probes denied with something other
	// than "not found" (e.g. a 500), which would hide the isolation result.
	ProbeUnexpected int `json:"probe_unexpected_errors"`
	// TopErrors counts the distinct error messages (first 120 characters).
	TopErrors map[string]int `json:"top_errors,omitempty"`
}

type scenarioReport struct {
	Scenario string                         `json:"scenario"`
	Duration string                         `json:"duration"`
	Tenants  map[string]map[string]*opStats `json:"tenants"`
	Checks   []string                       `json:"checks"`
	Failures []string                       `json:"failures"`
	Notes    []string                       `json:"notes,omitempty"`
}

func envInt(name string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(name)); err == nil && v > 0 {
		return v
	}
	return def
}

func envDuration(name string, def time.Duration) time.Duration {
	if v, err := time.ParseDuration(os.Getenv(name)); err == nil && v > 0 {
		return v
	}
	return def
}

func percentile(sorted []time.Duration, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(float64(len(sorted)-1) * p)
	return float64(sorted[idx].Microseconds()) / 1000
}

func summarize(samples []sample) map[string]*opStats {
	byOp := map[string][]sample{}
	for _, s := range samples {
		byOp[s.op] = append(byOp[s.op], s)
	}
	out := map[string]*opStats{}
	for op, list := range byOp {
		stats := &opStats{Count: len(list), TopErrors: map[string]int{}}
		latencies := []time.Duration{}
		for _, s := range list {
			switch {
			case s.err != nil && strings.Contains(s.err.Error(), "429"):
				stats.Throttled++
			case op == opCrossTenant && s.err == nil:
				stats.Violations++
			case op == opCrossTenant && !strings.Contains(strings.ToLower(s.err.Error()), "not found"):
				stats.ProbeUnexpected++
			case op != opCrossTenant && s.err != nil:
				stats.Errors++
			default:
				latencies = append(latencies, s.latency)
			}
		}
		for _, s := range list {
			if s.err != nil && !(op == opCrossTenant && strings.Contains(strings.ToLower(s.err.Error()), "not found")) {
				msg := s.err.Error()
				if len(msg) > 120 {
					msg = msg[:120]
				}
				stats.TopErrors[msg]++
			}
		}
		sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
		stats.P50Ms, stats.P95Ms, stats.P99Ms = percentile(latencies, 0.50), percentile(latencies, 0.95), percentile(latencies, 0.99)
		if served := stats.Count - stats.Throttled; served > 0 {
			stats.ErrorRate = float64(stats.Errors) / float64(served)
		}
		out[op] = stats
	}
	return out
}

type campaign struct {
	t        *testing.T
	ca       services.CAService
	tenants  []*tenantLoad
	adminDSN pgconfig.PostgresPSEConfig
}

func (c *campaign) op(tenant *tenantLoad, others []*tenantLoad) sample {
	roll := rand.Intn(100)
	start := time.Now()
	switch {
	case roll < 60:
		_, err := c.ca.GetCAByID(tenant.ctx, services.GetCAByIDInput{CAID: tenant.caID})
		return sample{op: opRead, at: start, latency: time.Since(start), err: err}
	case roll < 85:
		csr := tenant.csrs[rand.Intn(len(tenant.csrs))]
		crt, err := c.ca.SignCertificate(tenant.ctx, services.SignCertificateInput{CAID: tenant.caID, CertRequest: (*models.X509CertificateRequest)(csr)})
		if err == nil {
			tenant.mu.Lock()
			tenant.certs = append(tenant.certs, crt.SerialNumber)
			tenant.mu.Unlock()
		}
		return sample{op: opSign, at: start, latency: time.Since(start), err: err}
	default:
		other := others[rand.Intn(len(others))]
		_, err := c.ca.GetCAByID(tenant.ctx, services.GetCAByIDInput{CAID: other.caID})
		return sample{op: opCrossTenant, at: start, latency: time.Since(start), err: err}
	}
}

// run drives every tenant at its rate for the duration and returns the samples
// per tenant. hook, if set, runs once at mid-duration (fault injection).
func (c *campaign) run(duration time.Duration, rps map[string]int, hook func()) map[string][]sample {
	var wg sync.WaitGroup
	var mu sync.Mutex
	results := map[string][]sample{}
	deadline := time.Now().Add(duration)
	var inflight int64
	for _, tenant := range c.tenants {
		others := []*tenantLoad{}
		for _, o := range c.tenants {
			if o != tenant {
				others = append(others, o)
			}
		}
		wg.Add(1)
		go func(tenant *tenantLoad, others []*tenantLoad) {
			defer wg.Done()
			ticker := time.NewTicker(time.Second / time.Duration(rps[tenant.id]))
			defer ticker.Stop()
			var local sync.WaitGroup
			for now := range ticker.C {
				if now.After(deadline) {
					break
				}
				local.Add(1)
				atomic.AddInt64(&inflight, 1)
				go func() {
					defer local.Done()
					defer atomic.AddInt64(&inflight, -1)
					s := c.op(tenant, others)
					mu.Lock()
					results[tenant.id] = append(results[tenant.id], s)
					mu.Unlock()
				}()
			}
			local.Wait()
		}(tenant, others)
	}
	if hook != nil {
		time.Sleep(duration / 2)
		hook()
	}
	wg.Wait()
	return results
}

func (c *campaign) report(name string, duration time.Duration, results map[string][]sample) *scenarioReport {
	r := &scenarioReport{Scenario: name, Duration: duration.String(), Tenants: map[string]map[string]*opStats{}}
	for tenantID, samples := range results {
		r.Tenants[tenantID] = summarize(samples)
	}
	return r
}

func checkSLOs(r *scenarioReport, tenantIDs []string, allowThrottle map[string]bool) {
	for _, id := range tenantIDs {
		stats := r.Tenants[id]
		for op, s := range stats {
			label := fmt.Sprintf("%s %s", id[len(id)-2:], op)
			if s.Violations > 0 {
				r.Failures = append(r.Failures, fmt.Sprintf("%s: %d cross-tenant reads succeeded", label, s.Violations))
			}
			if s.ProbeUnexpected > 0 {
				r.Failures = append(r.Failures, fmt.Sprintf("%s: %d cross-tenant probes failed with an unexpected error", label, s.ProbeUnexpected))
			}
			if op == opCrossTenant {
				continue
			}
			if s.Throttled > 0 && !allowThrottle[id] {
				r.Failures = append(r.Failures, fmt.Sprintf("%s: %d requests throttled for a tenant within its quota", label, s.Throttled))
			}
			limit := apiP95Limit
			if op == opSign {
				limit = pkiP95Limit
			}
			if s.P95Ms > float64(limit.Milliseconds()) {
				r.Failures = append(r.Failures, fmt.Sprintf("%s: p95 %.1f ms over %v", label, s.P95Ms, limit))
			}
			if s.ErrorRate > errorRateMax {
				r.Failures = append(r.Failures, fmt.Sprintf("%s: error rate %.2f%% over 1%%", label, s.ErrorRate*100))
			}
		}
	}
	r.Checks = append(r.Checks, "p95 API < 500 ms, p95 PKI < 2 s, error rate < 1%, zero cross-tenant reads")
}

func setup(t *testing.T, tenantCount int, rateLimit cconfig.HttpServerTenantRateLimit) *campaign {
	t.Helper()
	tenantIDs := make([]string, tenantCount)
	for i := range tenantIDs {
		tenantIDs[i] = fmt.Sprintf("00000000-0000-0000-0000-0000000001%02d", i)
	}
	storage, err := tests.PreparePostgresForTest([]string{"ca", "kms"}, tenantIDs...)
	if err != nil {
		t.Fatalf("postgres: %s", err)
	}
	t.Cleanup(storage.AfterSuite)
	if err := storage.BeforeEach(); err != nil {
		t.Fatalf("seed: %s", err)
	}
	crypto := tests.PrepareCryptoEnginesForTest([]tests.CryptoEngine{tests.GOLANG})
	t.Cleanup(crypto.AfterSuite)
	if err := crypto.BeforeEach(); err != nil {
		t.Fatalf("crypto: %s", err)
	}
	noBus := &tests.TestEventBusConfig{Config: cconfig.EventBusEngine{Enabled: false}}
	kms, err := tests.BuildKMSTestServer(storage, crypto, noBus, false, false)
	if err != nil {
		t.Fatalf("kms: %s", err)
	}
	ca, err := tests.BuildCATestServer(storage, noBus, false, false, *kms)
	if err != nil {
		t.Fatalf("ca: %s", err)
	}

	options, err := tests.TestTenantRouteOptions(storage.Config)
	if err != nil {
		t.Fatalf("route options: %s", err)
	}
	options.RateLimit = rateLimit
	logger := logrus.NewEntry(logrus.New())
	logger.Logger.SetLevel(logrus.ErrorLevel)
	engine := routes.NewGinEngine(logger)
	routes.NewCAHTTPLayer(logger, engine.Group("/"), ca.Service, options)
	server := httptest.NewServer(engine)
	t.Cleanup(server.Close)

	pgCfg, err := cconfig.DecodeStruct[pgconfig.PostgresPSEConfig](storage.Config.Config)
	if err != nil {
		t.Fatalf("postgres config: %s", err)
	}
	c := &campaign{t: t, ca: sdk.NewHttpCAClient(server.Client(), server.URL), adminDSN: pgCfg}
	for _, id := range tenantIDs {
		ctx := tests.TenantContextFor(id, "load-"+id)
		profile, err := ca.Service.CreateIssuanceProfile(ctx, services.CreateIssuanceProfileInput{
			Profile: models.IssuanceProfile{Validity: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour)}},
		})
		if err != nil {
			t.Fatalf("profile %s: %s", id, err)
		}
		created, err := ca.Service.CreateCA(ctx, services.CreateCAInput{
			ID: "load-ca-" + id, KeyMetadata: models.KeyMetadata{Type: models.KeyType(x509.ECDSA), Bits: 256},
			Subject: models.Subject{CommonName: "Load CA"}, ProfileID: profile.ID,
			CAExpiration: models.Validity{Type: models.Duration, Duration: models.TimeDuration(24 * time.Hour)},
		})
		if err != nil {
			t.Fatalf("CA %s: %s", id, err)
		}
		tenant := &tenantLoad{id: id, ctx: ctx, caID: created.ID}
		for i := 0; i < 20; i++ {
			key, _ := chelpers.GenerateECDSAKey(elliptic.P256())
			csr, err := chelpers.GenerateCertificateRequest(models.Subject{CommonName: fmt.Sprintf("load-%d", i)}, key)
			if err != nil {
				t.Fatalf("csr: %s", err)
			}
			tenant.csrs = append(tenant.csrs, csr)
		}
		c.tenants = append(c.tenants, tenant)
	}
	return c
}

func terminateDatabaseConnections(t *testing.T, cfg pgconfig.PostgresPSEConfig) int64 {
	db, err := postgres.CreatePostgresDBConnection(logrus.NewEntry(logrus.New()), cfg, "postgres")
	if err != nil {
		t.Logf("fault injection: could not connect: %s", err)
		return 0
	}
	sqlDB, _ := db.DB()
	defer sqlDB.Close()
	var terminated int64
	db.Raw("SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity WHERE datname IN ('ca','kms','controlplane') AND pid <> pg_backend_pid()").Scan(&terminated)
	return terminated
}

func TestLoadCampaign(t *testing.T) {
	tenantCount := envInt("LOAD_TENANTS", 4)
	duration := envDuration("LOAD_DURATION", 30*time.Second)
	baseRPS := envInt("LOAD_RPS", 10)
	noisy := envInt("LOAD_NOISY_FACTOR", 8)
	reports := []*scenarioReport{}

	// L-01: all tenants at base load, no quota enforcement.
	{
		c := setup(t, tenantCount, cconfig.HttpServerTenantRateLimit{})
		rps := map[string]int{}
		ids := []string{}
		for _, tenant := range c.tenants {
			rps[tenant.id] = baseRPS
			ids = append(ids, tenant.id)
		}
		r := c.report("L-01 steady multi-tenant", duration, c.run(duration, rps, nil))
		checkSLOs(r, ids, nil)
		reports = append(reports, r)
	}

	// L-02: tenant 0 sends noisy×base while the quota is set to 2×base; the
	// others stay at base. The noisy tenant must be throttled and the others
	// must keep their SLOs without throttling.
	{
		limit := cconfig.HttpServerTenantRateLimit{Enabled: true, RequestsPerSecond: float64(2 * baseRPS), Burst: 2 * baseRPS}
		c := setup(t, tenantCount, limit)
		rps := map[string]int{}
		ids := []string{}
		for i, tenant := range c.tenants {
			rps[tenant.id] = baseRPS
			if i == 0 {
				rps[tenant.id] = noisy * baseRPS
			}
			ids = append(ids, tenant.id)
		}
		r := c.report("L-02 noisy neighbour with per-tenant quota", duration, c.run(duration, rps, nil))
		noisyID := c.tenants[0].id
		checkSLOs(r, ids[1:], nil)
		throttled := 0
		for _, s := range r.Tenants[noisyID] {
			throttled += s.Throttled
		}
		if throttled == 0 {
			r.Failures = append(r.Failures, "noisy tenant was never throttled")
		}
		r.Notes = append(r.Notes, fmt.Sprintf("noisy tenant %s: %d requests throttled (429); quota %.0f req/s burst %d", noisyID, throttled, limit.RequestsPerSecond, limit.Burst))
		reports = append(reports, r)
	}

	// L-03: all PostgreSQL connections are terminated at mid-run. Requests may
	// fail briefly; the service must recover and never return another
	// tenant's data.
	{
		c := setup(t, tenantCount, cconfig.HttpServerTenantRateLimit{})
		rps := map[string]int{}
		for _, tenant := range c.tenants {
			rps[tenant.id] = baseRPS
		}
		var terminated int64
		var faultAt time.Time
		results := c.run(duration, rps, func() {
			faultAt = time.Now()
			terminated = terminateDatabaseConnections(t, c.adminDSN)
		})
		r := c.report("L-03 database connection loss", duration, results)
		failed := 0
		var lastFailure, firstSuccessAfterFailures time.Time
		for _, tenant := range c.tenants {
			for _, s := range r.Tenants[tenant.id] {
				if s.Violations > 0 {
					r.Failures = append(r.Failures, fmt.Sprintf("tenant %s: %d cross-tenant reads succeeded", tenant.id, s.Violations))
				}
				failed += s.Errors
			}
			for _, s := range results[tenant.id] {
				if s.op != opCrossTenant && s.err != nil && s.at.After(lastFailure) {
					lastFailure = s.at
				}
			}
		}
		for _, samples := range results {
			for _, s := range samples {
				if s.op != opCrossTenant && s.err == nil && s.at.After(lastFailure) &&
					(firstSuccessAfterFailures.IsZero() || s.at.Before(firstSuccessAfterFailures)) {
					firstSuccessAfterFailures = s.at
				}
			}
		}
		recovery := time.Duration(0)
		if !lastFailure.IsZero() {
			if firstSuccessAfterFailures.IsZero() {
				r.Failures = append(r.Failures, "no successful request after the last failure: the service did not recover")
			} else {
				recovery = firstSuccessAfterFailures.Sub(faultAt)
			}
		}
		r.Checks = append(r.Checks, "zero cross-tenant reads during and after the fault; recovery after connection loss")
		r.Notes = append(r.Notes, fmt.Sprintf("terminated %d database connections; %d failed requests; recovered %.2fs after the fault (first success after the last failure)", terminated, failed, recovery.Seconds()))
		reports = append(reports, r)
	}

	encoded, _ := json.MarshalIndent(reports, "", "  ")
	if path := os.Getenv("LOAD_REPORT"); path != "" {
		if err := os.WriteFile(path, encoded, 0o644); err != nil {
			t.Errorf("could not write report: %s", err)
		}
	}
	t.Logf("load campaign report:\n%s", encoded)
	failures := []string{}
	for _, r := range reports {
		for _, f := range r.Failures {
			failures = append(failures, r.Scenario+": "+f)
		}
	}
	if len(failures) > 0 {
		t.Fatal(errors.New(strings.Join(failures, "\n")))
	}
}
