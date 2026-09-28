package main

import (
	"strings"
	"testing"
	"time"
)

const v1Tenant = "00000000-0000-0000-0000-000000000002"

func TestV1IsDisabledByDefault(t *testing.T) {
	opts, err := parse(t)
	if err != nil {
		t.Fatal(err)
	}
	v1 := opts.v1Config()
	if v1.DefaultTenantID != "" || !v1.SunsetAt.IsZero() {
		t.Fatalf("v1 configurado por defecto: %+v (P3: 503 sin opciones)", v1)
	}
}

func TestV1WithBothOptionsIsConfigured(t *testing.T) {
	opts, err := parse(t, "-v1-default-tenant", v1Tenant, "-v1-sunset", "2031-01-02T03:04:05Z")
	if err != nil {
		t.Fatal(err)
	}
	v1 := opts.v1Config()
	want := time.Date(2031, 1, 2, 3, 4, 5, 0, time.UTC)
	if v1.DefaultTenantID != v1Tenant || !v1.SunsetAt.Equal(want) {
		t.Fatalf("v1 %+v, se esperaba tenant %s y sunset %s", v1, v1Tenant, want)
	}
}

func TestV1WithOnlyOneOptionIsRejectedNamingTheMissingOne(t *testing.T) {
	_, err := parse(t, "-v1-default-tenant", v1Tenant)
	if err == nil || !strings.Contains(err.Error(), "-v1-sunset") {
		t.Errorf("solo tenant: error %v, se esperaba uno que nombre -v1-sunset", err)
	}
	_, err = parse(t, "-v1-sunset", "2031-01-02T03:04:05Z")
	if err == nil || !strings.Contains(err.Error(), "-v1-default-tenant") {
		t.Errorf("solo sunset: error %v, se esperaba uno que nombre -v1-default-tenant", err)
	}
}

func TestV1RejectsInvalidValues(t *testing.T) {
	for _, tenant := range []string{"default", "00000000-0000-0000-0000-00000000000", "not-a-uuid-at-all-0000000000000000"} {
		if _, err := parse(t, "-v1-default-tenant", tenant, "-v1-sunset", "2031-01-02T03:04:05Z"); err == nil || !strings.Contains(err.Error(), "-v1-default-tenant") {
			t.Errorf("tenant %q: error %v", tenant, err)
		}
	}
	for _, sunset := range []string{"2031-01-02", "tomorrow", "2031-13-01T00:00:00Z"} {
		if _, err := parse(t, "-v1-default-tenant", v1Tenant, "-v1-sunset", sunset); err == nil || !strings.Contains(err.Error(), "-v1-sunset") {
			t.Errorf("sunset %q: error %v", sunset, err)
		}
	}
}
