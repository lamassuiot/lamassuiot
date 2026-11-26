package config

import (
	"strings"
	"testing"
	"time"
)

func TestValidatedSSELimits(t *testing.T) {
	tests := []struct {
		name         string
		subscribers  int
		duration     time.Duration
		wantSubs     int
		wantDuration time.Duration
		expectedErr  string
	}{
		{name: "UnsetUsesHubDefaults"},
		{name: "Configured", subscribers: 5, duration: 2 * time.Minute, wantSubs: 5, wantDuration: 2 * time.Minute},
		{name: "NegativeSubscribers", subscribers: -1, expectedErr: "sse_max_subscribers"},
		{name: "NegativeDuration", duration: -time.Minute, expectedErr: "sse_max_stream_duration"},
		// A YAML integer without a unit decodes as nanoseconds: 600 meant as 600 s must not end every stream at once.
		{name: "UnitlessDuration", duration: 600, expectedErr: "sse_max_stream_duration must be 0 (default) or at least 1s"},
		{name: "MinimumDuration", duration: time.Second, wantDuration: time.Second},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conf := DeviceManagerConfig{SSEMaxSubscribers: tc.subscribers, SSEMaxStreamDuration: tc.duration}
			subs, duration, err := conf.ValidatedSSELimits()
			if tc.expectedErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.expectedErr) {
					t.Fatalf("expected error containing %q. Got %v", tc.expectedErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
			if subs != tc.wantSubs || duration != tc.wantDuration {
				t.Fatalf("expected (%d, %s). Got (%d, %s)", tc.wantSubs, tc.wantDuration, subs, duration)
			}
		})
	}
}
