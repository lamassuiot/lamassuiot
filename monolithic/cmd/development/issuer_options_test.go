package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lamassuiot/lamassuiot/monolithic/v3/pkg/devpki"
)

// Issuer con puntos y mayúsculas: se conserva exacto (requisito 4.2).
const externalIssuer = "https://Keycloak.Example.com:8443/realms/Lamassu.Dev"

func writeCAFile(t *testing.T) string {
	t.Helper()
	ca, err := devpki.NewCA("external IdP CA")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "idp-ca.crt")
	if err := os.WriteFile(path, ca.CertPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDevIssuerIsEnabledByDefaultWithoutExternalIssuers(t *testing.T) {
	opts, err := parse(t)
	if err != nil {
		t.Fatal(err)
	}
	if !opts.devIssuer {
		t.Error("el emisor local debe estar activo por defecto (P2)")
	}
	if len(opts.externalIssuers) != 0 || len(opts.issuerCAFiles) != 0 {
		t.Errorf("issuers externos por defecto: %v %v", opts.externalIssuers, opts.issuerCAFiles)
	}
}

func TestIssuerOptionIsRepeatableAndKeepsIssuerExact(t *testing.T) {
	caFile := writeCAFile(t)
	opts, err := parse(t,
		"-issuer", "issuer="+externalIssuer+",jwks="+externalIssuer+"/protocol/openid-connect/certs",
		"-issuer", "issuer=https://idp2.local/realms/b,jwks=https://idp2.local/realms/b/certs",
		"-issuer-ca-file", caFile,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(opts.externalIssuers) != 2 {
		t.Fatalf("issuers externos: %v", opts.externalIssuers)
	}
	first := opts.externalIssuers[0]
	if first.Issuer != externalIssuer || first.JWKSURL != externalIssuer+"/protocol/openid-connect/certs" {
		t.Errorf("issuer %+v, se esperaba %q exacto", first, externalIssuer)
	}
	if opts.externalIssuers[1].Issuer != "https://idp2.local/realms/b" {
		t.Errorf("segundo issuer %+v", opts.externalIssuers[1])
	}
	if len(opts.issuerCAFiles) != 1 || opts.issuerCAFiles[0] != caFile {
		t.Errorf("CA de issuers %v", opts.issuerCAFiles)
	}
	if !opts.devIssuer {
		t.Error("-issuer no debe desactivar el emisor local (se aceptan juntos)")
	}
}

func TestIssuerOptionRejectsMalformedValues(t *testing.T) {
	for _, value := range []string{
		"",
		externalIssuer,
		"issuer=" + externalIssuer,
		"jwks=https://idp.local/certs",
		"issuer=,jwks=https://idp.local/certs",
		"issuer=" + externalIssuer + ",jwks=",
		"issuer=" + externalIssuer + ",jwks=https://idp.local/certs,extra=1",
		"iss=" + externalIssuer + ",jwks=https://idp.local/certs",
	} {
		if _, err := parse(t, "-issuer", value); err == nil || !strings.Contains(err.Error(), "-issuer") {
			t.Errorf("-issuer %q: error %v, se esperaba uno que nombre -issuer", value, err)
		}
	}
}

func TestIssuerOptionRejectsNonHTTPSJWKS(t *testing.T) {
	for _, jwks := range []string{"http://idp.local/certs", "idp.local/certs", "https:///certs"} {
		_, err := parse(t, "-issuer", "issuer="+externalIssuer+",jwks="+jwks)
		if err == nil || !strings.Contains(err.Error(), "https") {
			t.Errorf("jwks %q: error %v, se esperaba uno que pida https", jwks, err)
		}
	}
}

func TestIssuerCAFileMustBeReadablePEM(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.crt")
	if _, err := parse(t, "-issuer-ca-file", missing); err == nil || !strings.Contains(err.Error(), "-issuer-ca-file") {
		t.Errorf("fichero inexistente: error %v", err)
	}
	notPEM := filepath.Join(t.TempDir(), "not.pem")
	if err := os.WriteFile(notPEM, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := parse(t, "-issuer-ca-file", notPEM); err == nil || !strings.Contains(err.Error(), "-issuer-ca-file") {
		t.Errorf("fichero sin PEM: error %v", err)
	}
}

func TestDisablingDevIssuerRequiresAnExternalIssuer(t *testing.T) {
	if _, err := parse(t, "-dev-issuer=false"); err == nil || !strings.Contains(err.Error(), "-issuer") {
		t.Errorf("-dev-issuer=false sin -issuer: error %v", err)
	}
	opts, err := parse(t, "-dev-issuer=false", "-issuer", "issuer="+externalIssuer+",jwks=https://idp.local/certs")
	if err != nil {
		t.Fatal(err)
	}
	if opts.devIssuer {
		t.Error("-dev-issuer=false ignorado")
	}
}
