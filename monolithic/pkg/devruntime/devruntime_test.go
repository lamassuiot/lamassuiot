package devruntime

import (
	"os"
	"path/filepath"
	"testing"

	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/monolithic/v3/pkg/devprofile"
	"github.com/lamassuiot/lamassuiot/monolithic/v3/pkg/monoconfig"
)

func TestStartWritesArtifactsWithRestrictedPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "runtime")
	rt, err := Start(Options{Dir: dir, DevIssuer: true})
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()

	info, err := os.Stat(dir)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("directorio %v, permisos %v; se esperaba 0700", err, info.Mode().Perm())
	}
	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		want := os.FileMode(0o600)
		if info.IsDir() {
			want = 0o700
		}
		if info.Mode().Perm() != want {
			t.Errorf("%s: permisos %v, se esperaba %v", path, info.Mode().Perm(), want)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestStartConfiguresLocalIssuerFirstAndTrustsItsCA(t *testing.T) {
	ext := cconfig.HttpServerJWTIssuer{Issuer: "https://idp.example.com/realms/X", JWKSURL: "https://idp.example.com/realms/X/certs"}
	rt, err := Start(Options{Dir: t.TempDir(), DevIssuer: true, ExternalIssuers: []cconfig.HttpServerJWTIssuer{ext}, ExternalCAFiles: []string{"/tmp/idp-ca.crt"}})
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	mt := rt.Multitenant
	if len(mt.Issuers) != 2 || mt.Issuers[0].Issuer != rt.Issuer.Issuer() || mt.Issuers[0].JWKSURL != rt.Issuer.JWKSURL() || mt.Issuers[1] != ext {
		t.Fatalf("issuers %+v", mt.Issuers)
	}
	if len(mt.JWKSTrustedCAFiles) != 2 || filepath.Base(mt.JWKSTrustedCAFiles[0]) != "monolith-ca.crt" || mt.JWKSTrustedCAFiles[1] != "/tmp/idp-ca.crt" {
		t.Fatalf("CA de confianza %v", mt.JWKSTrustedCAFiles)
	}
	provisioners := rt.DefaultProvisioners()
	if len(provisioners) != 1 || provisioners[0].Issuer != rt.Issuer.Issuer() || provisioners[0].Subject != DefaultProvisionerSubject {
		t.Fatalf("provisioners por defecto %+v", provisioners)
	}
	// La config generada es válida para devprofile.
	if _, err := devprofile.Build(monoconfig.MonolithicConfig{Multitenant: mt}); err != nil {
		t.Fatalf("devprofile.Build rechaza la config de devruntime: %v", err)
	}
}

func TestStartWithoutAnyIssuerFails(t *testing.T) {
	if _, err := Start(Options{Dir: t.TempDir()}); err == nil {
		t.Fatal("Start sin emisor local ni issuers externos no falla")
	}
}

func TestStartWithOnlyExternalIssuer(t *testing.T) {
	ext := cconfig.HttpServerJWTIssuer{Issuer: "https://idp.example.com/realms/X", JWKSURL: "https://idp.example.com/realms/X/certs"}
	rt, err := Start(Options{Dir: t.TempDir(), ExternalIssuers: []cconfig.HttpServerJWTIssuer{ext}})
	if err != nil {
		t.Fatal(err)
	}
	if rt.Issuer != nil || len(rt.Multitenant.Issuers) != 1 || len(rt.DefaultProvisioners()) != 0 {
		t.Fatalf("runtime inesperado: issuer=%v %+v", rt.Issuer, rt.Multitenant.Issuers)
	}
}

func TestInternalCertificatesAreSignedByTheInternalCA(t *testing.T) {
	rt, err := Start(Options{Dir: t.TempDir(), DevIssuer: true})
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	in := rt.Multitenant.InternalTLS
	for _, svc := range monoconfig.AllServices {
		files, ok := in.Services[svc]
		if !ok {
			t.Fatalf("sin certificado interno para %s", svc)
		}
		for _, f := range []string{files.CertFile, files.KeyFile, in.CAFile} {
			if _, err := os.Stat(f); err != nil {
				t.Errorf("%s: %v", svc, err)
			}
		}
	}
	caPEM, err := os.ReadFile(in.CAFile)
	if err != nil || string(caPEM) != string(rt.InternalCA.CertPEM()) {
		t.Fatalf("%s no contiene la CA interna (¿lo pisa el certificado de un servicio?): %v", in.CAFile, err)
	}
	if rt.InternalCA.Certificate().Equal(rt.CA.Certificate()) {
		t.Fatal("la CA interna y la del emisor deben ser distintas")
	}
}
