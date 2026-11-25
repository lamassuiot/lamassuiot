package config

import (
	"strings"
	"testing"
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
