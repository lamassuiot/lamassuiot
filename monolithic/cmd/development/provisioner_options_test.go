package main

import (
	"strings"
	"testing"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/config"
)

func TestNoExplicitProvisionersByDefault(t *testing.T) {
	opts, err := parse(t)
	if err != nil {
		t.Fatal(err)
	}
	if len(opts.provisioners) != 0 {
		t.Errorf("provisioners explícitos por defecto: %v", opts.provisioners)
	}
	local := []config.TenantManagerProvisioner{{Issuer: "https://127.0.0.1:1/realms/lamassu-dev", Subject: "provisioner"}}
	if got := opts.effectiveProvisioners(local); len(got) != 1 || got[0] != local[0] {
		t.Errorf("sin -provisioner se esperaba el del emisor local, hay %v", got)
	}
}

func TestProvisionerOptionIsRepeatableAndReplacesTheDefault(t *testing.T) {
	opts, err := parse(t,
		"-provisioner", externalIssuer+"|ops-bot",
		"-provisioner", "https://idp2.local/realms/b|Alice.Admin",
	)
	if err != nil {
		t.Fatal(err)
	}
	want := []config.TenantManagerProvisioner{
		{Issuer: externalIssuer, Subject: "ops-bot"},
		{Issuer: "https://idp2.local/realms/b", Subject: "Alice.Admin"},
	}
	local := []config.TenantManagerProvisioner{{Issuer: "https://127.0.0.1:1/realms/lamassu-dev", Subject: "provisioner"}}
	got := opts.effectiveProvisioners(local)
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("provisioners %v, se esperaba %v", got, want)
	}
}

func TestProvisionerOptionRejectsMalformedValues(t *testing.T) {
	for _, value := range []string{"", "ops-bot", externalIssuer + "|", "|ops-bot", externalIssuer + "|a|b"} {
		if _, err := parse(t, "-provisioner", value); err == nil || !strings.Contains(err.Error(), "-provisioner") {
			t.Errorf("-provisioner %q: error %v, se esperaba uno que nombre -provisioner", value, err)
		}
	}
}
