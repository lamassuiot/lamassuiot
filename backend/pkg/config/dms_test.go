package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cconfig "github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
)

func TestCRLCacheConfigMaxBytes(t *testing.T) {
	tests := []struct {
		name        string
		maxSizeMB   int
		want        uint64
		expectedErr string
	}{
		{name: "UnsetUsesServiceDefault", maxSizeMB: 0, want: 0},
		{name: "Megabytes", maxSizeMB: 1024, want: 1073741824},
		{name: "Negative", maxSizeMB: -1, expectedErr: "crl_cache.max_size_mb"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CRLCacheConfig{MaxSizeMB: tc.maxSizeMB}.MaxBytes()
			if tc.expectedErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.expectedErr) {
					t.Fatalf("expected error containing %q. Got %v", tc.expectedErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
			if got != tc.want {
				t.Fatalf("expected %d bytes. Got %d", tc.want, got)
			}
		})
	}
}

func TestCRLCacheConfigMaxTTL(t *testing.T) {
	tests := []struct {
		name        string
		maxTTL      time.Duration
		want        time.Duration
		expectedErr string
	}{
		{name: "UnsetUsesServiceDefault", maxTTL: 0, want: 0},
		{name: "Configured", maxTTL: 30 * time.Minute, want: 30 * time.Minute},
		{name: "Negative", maxTTL: -time.Minute, expectedErr: "crl_cache.max_ttl"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CRLCacheConfig{MaxTTL: tc.maxTTL}.ValidatedMaxTTL()
			if tc.expectedErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.expectedErr) {
					t.Fatalf("expected error containing %q. Got %v", tc.expectedErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
			if got != tc.want {
				t.Fatalf("expected %s. Got %s", tc.want, got)
			}
		})
	}
}

// TestDMSConfigLoadsCRLCacheSettings checks that the CRL cache settings are read from the configuration file, with
// max_ttl written as a Go duration.
func TestDMSConfigLoadsCRLCacheSettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte("crl_cache:\n  max_ttl: 30m\n  max_size_mb: 256\n"), 0600); err != nil {
		t.Fatalf("could not write config: %s", err)
	}
	t.Setenv("LAMASSU_CONFIG_FILE", path)

	conf, err := cconfig.LoadConfig[DMSconfig](nil)
	if err != nil {
		t.Fatalf("could not load config: %s", err)
	}
	if conf.CRLCache.MaxTTL != 30*time.Minute || conf.CRLCache.MaxSizeMB != 256 {
		t.Fatalf("expected max_ttl 30m and max_size_mb 256. Got %s and %d", conf.CRLCache.MaxTTL, conf.CRLCache.MaxSizeMB)
	}
}
