package services

import (
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// crlDER returns a CRL signed by signer with n revoked entries; a zero nextUpdate omits the field.
func crlDER(t *testing.T, signer *revocationTestCA, thisUpdate, nextUpdate time.Time, n int) []byte {
	t.Helper()
	entries := make([]x509.RevocationListEntry, n)
	for i := range entries {
		entries[i] = x509.RevocationListEntry{SerialNumber: big.NewInt(int64(1000 + i)), RevocationTime: thisUpdate}
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    big.NewInt(1),
		ThisUpdate:                thisUpdate,
		NextUpdate:                nextUpdate,
		RevokedCertificateEntries: entries,
	}, signer.cert, signer.key)
	if err != nil {
		t.Fatalf("could not create CRL: %s", err)
	}
	return der
}

// countingServer serves body() to every request and counts them; body returning nil answers 500.
func countingServer(t *testing.T, body func() []byte) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	requests := &atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		b := body()
		if b == nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Write(b)
	}))
	t.Cleanup(srv.Close)
	return srv, requests
}

func staticBody(b []byte) func() []byte {
	return func() []byte { return b }
}

func TestCRLCacheTTL(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name       string
		thisUpdate time.Time
		nextUpdate time.Time
		want       time.Duration
		wantNoTTL  bool
	}{
		{name: "NextUpdateBeforeMaxTTL", thisUpdate: now.Add(-time.Hour), nextUpdate: now.Add(10 * time.Minute), want: 10 * time.Minute},
		{name: "NextUpdateAfterMaxTTL", thisUpdate: now.Add(-time.Hour), nextUpdate: now.Add(3 * time.Hour), want: time.Hour},
		{name: "NextUpdatePassed", thisUpdate: now.Add(-time.Hour), nextUpdate: now.Add(-time.Minute), wantNoTTL: true},
		{name: "NoNextUpdateMaxAgeFirst", thisUpdate: now.Add(-23*time.Hour - 30*time.Minute), want: 30 * time.Minute},
		{name: "NoNextUpdateMaxTTLFirst", thisUpdate: now.Add(-2 * time.Hour), want: time.Hour},
		{name: "NoNextUpdateTooOld", thisUpdate: now.Add(-25 * time.Hour), wantNoTTL: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := crlCacheTTL(&x509.RevocationList{ThisUpdate: tc.thisUpdate, NextUpdate: tc.nextUpdate}, now, time.Hour)
			if tc.wantNoTTL {
				if got > 0 {
					t.Fatalf("expected a non-positive TTL. Got %s", got)
				}
				return
			}
			if got != tc.want {
				t.Fatalf("expected TTL %s. Got %s", tc.want, got)
			}
		})
	}
}

func TestCRLCost(t *testing.T) {
	ca := newRevocationTestCA(t, "cost-ca")
	crl, err := x509.ParseRevocationList(crlDER(t, ca, time.Now(), time.Now().Add(time.Hour), 3))
	if err != nil {
		t.Fatalf("could not parse CRL: %s", err)
	}
	url := "http://crl.example.com/ca.crl"
	if want := 2048 + uint64(len(url)) + uint64(len(crl.Raw)) + 3*512; crlCost(url, crl) != want {
		t.Fatalf("expected cost %d. Got %d", want, crlCost(url, crl))
	}
}

// TestCRLCacheBudgetCountsFixedOverhead checks that the budget accounts for the memory every cached CRL holds besides
// its encoding and entries, so many small CRLs cannot exceed it.
func TestCRLCacheBudgetCountsFixedOverhead(t *testing.T) {
	ca := newRevocationTestCA(t, "overhead-ca")
	der := crlDER(t, ca, time.Now().Add(-time.Minute), time.Now().Add(time.Hour), 0)
	c := newCRLCache(5000, 0) // room for two empty CRLs, not three

	for i := range 3 {
		srv, _ := countingServer(t, staticBody(der))
		if _, _, err := c.get(srv.URL, ca.cert); err != nil {
			t.Fatalf("CRL %d: unexpected error: %s", i+1, err)
		}
	}
	if n := c.cache.Len(); n != 2 {
		t.Fatalf("expected 2 cached CRLs within the budget. Got %d", n)
	}
}

func TestCRLCacheHitWithinTTL(t *testing.T) {
	ca := newRevocationTestCA(t, "hit-ca")
	srv, requests := countingServer(t, staticBody(crlDER(t, ca, time.Now().Add(-time.Minute), time.Now().Add(time.Hour), 0)))
	c := newCRLCache(0, 0)

	first, hit, err := c.get(srv.URL, ca.cert)
	if err != nil || hit {
		t.Fatalf("expected a miss without error. Got hit=%t err=%v", hit, err)
	}
	second, hit, err := c.get(srv.URL, ca.cert)
	if err != nil || !hit {
		t.Fatalf("expected a hit without error. Got hit=%t err=%v", hit, err)
	}
	if first != second {
		t.Fatalf("expected the cached CRL to be returned")
	}
	if n := requests.Load(); n != 1 {
		t.Fatalf("expected 1 download. Got %d", n)
	}
}

func TestCRLCacheRefetchAfterTTL(t *testing.T) {
	ca := newRevocationTestCA(t, "refetch-ca")
	srv, requests := countingServer(t, staticBody(crlDER(t, ca, time.Now().Add(-time.Minute), time.Now().Add(time.Hour), 0)))
	c := newCRLCache(0, 50*time.Millisecond)

	if _, _, err := c.get(srv.URL, ca.cert); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	time.Sleep(100 * time.Millisecond)
	_, hit, err := c.get(srv.URL, ca.cert)
	if err != nil || hit {
		t.Fatalf("expected a miss without error after the TTL. Got hit=%t err=%v", hit, err)
	}
	if n := requests.Load(); n != 2 {
		t.Fatalf("expected 2 downloads. Got %d", n)
	}
}

func TestCRLCacheTTLCappedByNextUpdate(t *testing.T) {
	ca := newRevocationTestCA(t, "nextupdate-ca")
	srv, _ := countingServer(t, staticBody(crlDER(t, ca, time.Now().Add(-time.Minute), time.Now().Add(10*time.Minute), 0)))
	c := newCRLCache(0, 0)

	crl, _, err := c.get(srv.URL, ca.cert)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	item := c.cache.Get(srv.URL)
	if item == nil {
		t.Fatalf("expected the CRL to be cached")
	}
	if diff := item.ExpiresAt().Sub(crl.NextUpdate); diff > time.Second || diff < -time.Second {
		t.Fatalf("expected the entry to expire at nextUpdate %s. Expires at %s", crl.NextUpdate, item.ExpiresAt())
	}
}

// TestCRLCacheUsesConfiguredMaxTTL checks that entries expire after the configured maximum TTL, 1 hour when unset,
// unless the CRL's nextUpdate comes first.
func TestCRLCacheUsesConfiguredMaxTTL(t *testing.T) {
	ca := newRevocationTestCA(t, "maxttl-ca")
	tests := []struct {
		name       string
		maxTTL     time.Duration
		nextUpdate time.Duration
		want       time.Duration
	}{
		{name: "Configured", maxTTL: 10 * time.Minute, nextUpdate: time.Hour, want: 10 * time.Minute},
		{name: "DefaultWhenUnset", maxTTL: 0, nextUpdate: 3 * time.Hour, want: time.Hour},
		{name: "NextUpdateFirst", maxTTL: 2 * time.Hour, nextUpdate: 30 * time.Minute, want: 30 * time.Minute},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := countingServer(t, staticBody(crlDER(t, ca, time.Now().Add(-time.Minute), time.Now().Add(tc.nextUpdate), 0)))
			c := newCRLCache(0, tc.maxTTL)

			if _, _, err := c.get(srv.URL, ca.cert); err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
			item := c.cache.Get(srv.URL)
			if item == nil {
				t.Fatalf("expected the CRL to be cached")
			}
			if diff := time.Until(item.ExpiresAt()) - tc.want; diff > 2*time.Second || diff < -2*time.Second {
				t.Fatalf("expected the entry to expire in %s. Expires in %s", tc.want, time.Until(item.ExpiresAt()))
			}
		})
	}
}

func TestCRLCacheHitDoesNotExtendExpiry(t *testing.T) {
	ca := newRevocationTestCA(t, "touch-ca")
	srv, _ := countingServer(t, staticBody(crlDER(t, ca, time.Now().Add(-time.Minute), time.Now().Add(time.Hour), 0)))
	c := newCRLCache(0, 0)

	if _, _, err := c.get(srv.URL, ca.cert); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	before := c.cache.Get(srv.URL).ExpiresAt()
	time.Sleep(20 * time.Millisecond)
	if _, hit, err := c.get(srv.URL, ca.cert); err != nil || !hit {
		t.Fatalf("expected a hit without error. Got hit=%t err=%v", hit, err)
	}
	if after := c.cache.Get(srv.URL).ExpiresAt(); !after.Equal(before) {
		t.Fatalf("expected expiry %s to stay unchanged. Got %s", before, after)
	}
}

func TestCRLCacheDoesNotCache(t *testing.T) {
	ca := newRevocationTestCA(t, "nocache-ca")
	otherCA := newRevocationTestCA(t, "nocache-other-ca")
	now := time.Now()

	tests := []struct {
		name        string
		body        func() []byte
		maxBytes    uint64
		expectedErr string // empty: the CRL is returned without error
	}{
		{name: "HTTPError", body: staticBody(nil), expectedErr: "status code 500"},
		{name: "Unparseable", body: staticBody([]byte("not a crl")), expectedErr: "could not decode CRL"},
		{name: "Stale", body: staticBody(crlDER(t, ca, now.Add(-2*time.Hour), now.Add(-time.Hour), 0))},
		{name: "FutureThisUpdate", body: staticBody(crlDER(t, ca, now.Add(time.Hour), now.Add(2*time.Hour), 0))},
		{name: "SignedByOtherCA", body: staticBody(crlDER(t, otherCA, now.Add(-time.Minute), now.Add(time.Hour), 0)), expectedErr: "could not validate CRL"},
		{name: "LargerThanBudget", body: staticBody(crlDER(t, ca, now.Add(-time.Minute), now.Add(time.Hour), 10)), maxBytes: 1024},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv, requests := countingServer(t, tc.body)
			c := newCRLCache(tc.maxBytes, 0)

			for i := range 2 {
				crl, hit, err := c.get(srv.URL, ca.cert)
				if hit {
					t.Fatalf("call %d: expected a miss", i+1)
				}
				if tc.expectedErr == "" {
					if err != nil || crl == nil {
						t.Fatalf("call %d: expected the CRL without error. Got %v", i+1, err)
					}
				} else if err == nil || !strings.Contains(err.Error(), tc.expectedErr) {
					t.Fatalf("call %d: expected error containing %q. Got %v", i+1, tc.expectedErr, err)
				}
			}
			if n := requests.Load(); n != 2 {
				t.Fatalf("expected 2 downloads. Got %d", n)
			}
			if c.cache.Get(srv.URL) != nil {
				t.Fatalf("expected nothing cached")
			}
		})
	}
}

func TestCRLCacheOversizedDoesNotEvictOthers(t *testing.T) {
	ca := newRevocationTestCA(t, "oversized-ca")
	now := time.Now()
	small, _ := countingServer(t, staticBody(crlDER(t, ca, now.Add(-time.Minute), now.Add(time.Hour), 0)))
	large, _ := countingServer(t, staticBody(crlDER(t, ca, now.Add(-time.Minute), now.Add(time.Hour), 20)))
	c := newCRLCache(4096, 0)

	if _, _, err := c.get(small.URL, ca.cert); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if _, _, err := c.get(large.URL, ca.cert); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if c.cache.Get(small.URL) == nil {
		t.Fatalf("expected the small CRL to stay cached")
	}
	if c.cache.Get(large.URL) != nil {
		t.Fatalf("expected the CRL larger than the budget not to be cached")
	}
}

func TestCRLCacheVerifiesSignatureOnHit(t *testing.T) {
	ca := newRevocationTestCA(t, "sig-ca")
	otherCA := newRevocationTestCA(t, "sig-other-ca")
	srv, requests := countingServer(t, staticBody(crlDER(t, ca, time.Now().Add(-time.Minute), time.Now().Add(time.Hour), 0)))
	c := newCRLCache(0, 0)

	if _, _, err := c.get(srv.URL, ca.cert); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	crl, hit, err := c.get(srv.URL, otherCA.cert)
	if !hit {
		t.Fatalf("expected a hit")
	}
	if err == nil || !strings.Contains(err.Error(), "could not validate CRL") || crl != nil {
		t.Fatalf("expected a signature error and no CRL. Got crl=%v err=%v", crl != nil, err)
	}
	if n := requests.Load(); n != 1 {
		t.Fatalf("expected 1 download. Got %d", n)
	}
}

func TestCRLCacheSingleDownloadUnderConcurrency(t *testing.T) {
	ca := newRevocationTestCA(t, "concurrent-ca")
	der := crlDER(t, ca, time.Now().Add(-time.Minute), time.Now().Add(time.Hour), 0)

	for _, tc := range []struct {
		name    string
		body    []byte
		wantErr bool
	}{
		{name: "Success", body: der},
		{name: "Failure", body: nil, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			release := make(chan struct{})
			srv, requests := countingServer(t, func() []byte {
				<-release
				return tc.body
			})
			c := newCRLCache(0, 0)

			const callers = 20
			errs := make([]error, callers)
			var wg sync.WaitGroup
			for i := range callers {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					_, _, errs[i] = c.get(srv.URL, ca.cert)
				}(i)
			}
			time.Sleep(50 * time.Millisecond)
			close(release)
			wg.Wait()

			if n := requests.Load(); n != 1 {
				t.Fatalf("expected 1 download. Got %d", n)
			}
			for i, err := range errs {
				if tc.wantErr != (err != nil) {
					t.Fatalf("caller %d: expected error=%t. Got %v", i, tc.wantErr, err)
				}
			}
		})
	}
}
