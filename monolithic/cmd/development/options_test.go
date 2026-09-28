package main

import (
	"io"
	"strings"
	"testing"
)

func parse(t *testing.T, args ...string) (*options, error) {
	t.Helper()
	return parseOptions(args, io.Discard)
}

func TestExternalPostgresHostWithoutPasswordIsRejected(t *testing.T) {
	_, err := parse(t, "-postgres-host", "db.local")
	if err == nil || !strings.Contains(err.Error(), "-postgres-admin-password") {
		t.Fatalf("error %v, se esperaba uno que pida -postgres-admin-password", err)
	}
}

func TestExternalPostgresOptionsWithoutHostAreRejected(t *testing.T) {
	for _, args := range [][]string{
		{"-postgres-port", "6543"},
		{"-postgres-admin-user", "admin"},
		{"-postgres-admin-password", "secret"},
	} {
		if _, err := parse(t, args...); err == nil || !strings.Contains(err.Error(), "-postgres-host") {
			t.Errorf("%v: error %v, se esperaba uno que pida -postgres-host", args, err)
		}
	}
}

func TestExternalPostgresInvalidPortIsRejected(t *testing.T) {
	for _, port := range []string{"70000", "-1"} {
		if _, err := parse(t, "-postgres-host", "db.local", "-postgres-admin-password", "s", "-postgres-port", port); err == nil {
			t.Errorf("puerto %s aceptado", port)
		}
	}
}

func TestExternalPostgresDefaults(t *testing.T) {
	opts, err := parse(t, "-postgres-host", "db.local", "-postgres-admin-password", "secret")
	if err != nil {
		t.Fatal(err)
	}
	ext := opts.externalPostgres()
	if ext == nil {
		t.Fatal("no se construyó la config de PostgreSQL externo")
	}
	if ext.Hostname != "db.local" || ext.Port != 5432 || ext.Username != "postgres" || string(ext.Password) != "secret" {
		t.Errorf("config externa %+v", *ext)
	}
}

func TestNoExternalPostgresByDefault(t *testing.T) {
	opts, err := parse(t)
	if err != nil {
		t.Fatal(err)
	}
	if opts.externalPostgres() != nil {
		t.Error("sin -postgres-host no debe haber PostgreSQL externo")
	}
}
