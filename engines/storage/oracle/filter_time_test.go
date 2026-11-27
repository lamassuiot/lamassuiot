package oracle

import (
	"testing"
	"time"
)

func TestParseFilterTime(t *testing.T) {
	for value, want := range map[string]time.Time{
		"2025-01-02T03:04:05.5Z":     time.Date(2025, 1, 2, 3, 4, 5, 500000000, time.UTC),
		"2025-01-02T03:04:05+02:00":  time.Date(2025, 1, 2, 1, 4, 5, 0, time.UTC),
		"2025-01-02 03:04:05+02:00":  time.Date(2025, 1, 2, 1, 4, 5, 0, time.UTC),
		"2025-01-02T03:04:05":        time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC),
		"2025-01-02 03:04:05.123456": time.Date(2025, 1, 2, 3, 4, 5, 123456000, time.UTC),
		"2025-01-02":                 time.Date(2025, 1, 2, 0, 0, 0, 0, time.UTC),
	} {
		got, err := ParseFilterTime(value)
		if err != nil || !got.Equal(want) {
			t.Errorf("ParseFilterTime(%q) = %s, %v; want %s", value, got, err, want)
		}
	}
	for _, value := range []string{"", "yesterday", "2025-13-01", "02/01/2025"} {
		if _, err := ParseFilterTime(value); err == nil {
			t.Errorf("ParseFilterTime(%q) accepted an invalid date", value)
		}
	}
}
