package config

import (
	"testing"
	"time"
)

func TestDecodeOracleDBConfigPoolDefaults(t *testing.T) {
	base := map[string]any{"connect_string": "db:1521/FREEPDB1", "username": "authz"}
	with := func(extra map[string]any) map[string]any {
		m := map[string]any{}
		for k, v := range base {
			m[k] = v
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	for _, tc := range []struct {
		name               string
		source             map[string]any
		wantOpen, wantIdle int
		wantLifetime       time.Duration
	}{
		{"omitted settings use the PostgreSQL limits", base, 25, 5, 5 * time.Minute},
		{"explicit settings are kept", with(map[string]any{"max_open_conns": 10, "max_idle_conns": 2, "conn_max_lifetime": "1m"}), 10, 2, time.Minute},
		{"idle default never exceeds an explicit open limit", with(map[string]any{"max_open_conns": 3}), 3, 3, 5 * time.Minute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := DecodeOracleDBConfig(tc.source)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.MaxOpenConns != tc.wantOpen || cfg.MaxIdleConns != tc.wantIdle || cfg.ConnMaxLifetime != tc.wantLifetime {
				t.Fatalf("pool = %d/%d/%s, want %d/%d/%s", cfg.MaxOpenConns, cfg.MaxIdleConns, cfg.ConnMaxLifetime, tc.wantOpen, tc.wantIdle, tc.wantLifetime)
			}
		})
	}
}
