package services

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/jellydator/ttlcache/v3"
	external_clients "github.com/lamassuiot/lamassuiot/v4/sdk/external"
	"golang.org/x/sync/singleflight"
)

const (
	// defaultCRLCacheMaxTTL bounds how long a downloaded CRL is reused when no maximum is configured, so a newly
	// published CRL is seen within that time.
	defaultCRLCacheMaxTTL = time.Hour
	// defaultCRLCacheMaxBytes is the memory budget of the CRL cache when none is configured, small enough for a DMS
	// container with a modest memory limit. Deployments that check many or large CRLs can raise it.
	defaultCRLCacheMaxBytes = uint64(256 << 20)
	// crlEntryMemoryEstimate is the heap a parsed CRL holds per revoked entry on top of its DER encoding. Measured at
	// 300–400 bytes on Go 1.27, which fills both RevokedCertificateEntries and the deprecated RevokedCertificates.
	crlEntryMemoryEstimate = 512
	// crlFixedMemoryEstimate is the heap every cached CRL holds besides its encoding and entries: the parsed
	// RevocationList with its issuer name and extensions, and the cache's item, list element and map slot. Measured at
	// about 1.4 KB for an empty CRL on Go 1.27; larger issuer names and RSA signatures add to it.
	crlFixedMemoryEstimate = 2048
)

// crlCache keeps the CRLs downloaded for client certificate revocation checks, keyed by distribution point URL.
// An entry expires after maxTTL or at the CRL's nextUpdate, whichever comes first, and reading it does not
// extend its expiry. Concurrent misses for the same URL share a single download. Cached CRLs are shared between
// goroutines and must not be modified.
type crlCache struct {
	cache    *ttlcache.Cache[string, *x509.RevocationList]
	group    singleflight.Group
	maxTTL   time.Duration
	maxBytes uint64
}

// newCRLCache returns a cache holding at most maxBytes of estimated CRL memory and keeping each CRL for at most
// maxTTL. A zero value uses defaultCRLCacheMaxBytes or defaultCRLCacheMaxTTL.
func newCRLCache(maxBytes uint64, maxTTL time.Duration) *crlCache {
	if maxBytes == 0 {
		maxBytes = defaultCRLCacheMaxBytes
	}
	if maxTTL == 0 {
		maxTTL = defaultCRLCacheMaxTTL
	}

	return &crlCache{
		cache: ttlcache.New(
			ttlcache.WithDisableTouchOnHit[string, *x509.RevocationList](),
			ttlcache.WithMaxCost(maxBytes, func(item ttlcache.CostItem[string, *x509.RevocationList]) uint64 {
				return crlCost(item.Key, item.Value)
			}),
		),
		maxTTL:   maxTTL,
		maxBytes: maxBytes,
	}
}

// get returns the CRL published at url, from the cache or downloaded, after verifying that issuer signed it. hit
// reports whether it came from the cache. A downloaded CRL is cached only when it is fresh, fits in the budget and
// was signed by issuer; otherwise it is still returned for this check.
func (c *crlCache) get(url string, issuer *x509.Certificate) (crl *x509.RevocationList, hit bool, err error) {
	if item := c.cache.Get(url); item != nil {
		crl, hit = item.Value(), true
	} else {
		v, err, _ := c.group.Do(url, func() (any, error) {
			// A flight for url that ended between the lookup above and this one has already cached the CRL.
			if item := c.cache.Get(url); item != nil {
				return item.Value(), nil
			}

			crl, err := external_clients.GetCRLResponse(url, nil, nil, false)
			if err != nil {
				return nil, err
			}

			now := time.Now()
			ttl := crlCacheTTL(crl, now, c.maxTTL)
			if ttl > 0 && crlCost(url, crl) <= c.maxBytes &&
				checkRevocationFreshness(crl.ThisUpdate, crl.NextUpdate, now) == nil &&
				crl.CheckSignatureFrom(issuer) == nil {
				c.cache.DeleteExpired()
				c.cache.Set(url, crl, ttl)
			}
			return crl, nil
		})
		if err != nil {
			return nil, false, err
		}
		crl = v.(*x509.RevocationList)
	}

	if err := crl.CheckSignatureFrom(issuer); err != nil {
		return nil, hit, fmt.Errorf("could not validate CRL: %w", err)
	}
	return crl, hit, nil
}

// crlCacheTTL returns how long crl may be cached at now: up to maxTTL and never past its nextUpdate, or, when it has
// none, past thisUpdate plus revocationMaxAgeWithoutNextUpdate. A non-positive result means it must not be cached.
func crlCacheTTL(crl *x509.RevocationList, now time.Time, maxTTL time.Duration) time.Duration {
	expiry := crl.NextUpdate
	if expiry.IsZero() {
		expiry = crl.ThisUpdate.Add(revocationMaxAgeWithoutNextUpdate)
	}
	return min(maxTTL, expiry.Sub(now))
}

// crlCost estimates the heap held by the CRL cached under url, in bytes.
func crlCost(url string, crl *x509.RevocationList) uint64 {
	return crlFixedMemoryEstimate + uint64(len(url)) + uint64(len(crl.Raw)) +
		crlEntryMemoryEstimate*uint64(len(crl.RevokedCertificateEntries))
}
