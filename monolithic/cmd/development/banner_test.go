package main

// Banner de arranque (spec 009, tarea 12; requisito 10.4).

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/monolithic/v3/pkg/devruntime"
	"github.com/lamassuiot/lamassuiot/monolithic/v3/pkg/monoconfig"
)

func TestRuntimeBannerDescribesProfileWithoutPrivateKeys(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "runtime")
	rt, err := devruntime.Start(devruntime.Options{Dir: dir, DevIssuer: true})
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	opts, err := parse(t, "-listen", "0.0.0.0")
	if err != nil {
		t.Fatal(err)
	}

	banner := renderBanner(bannerInfo{
		RuntimeDir:    dir,
		ListenAddress: "0.0.0.0",
		HTTPSPort:     8443,
		HTTPPort:      8080,
		Issuers:       rt.Multitenant.Issuers,
		LocalIssuer:   rt.Issuer,
		Provisioners:  rt.DefaultProvisioners(),
		V1:            monoconfig.V1Config{},
		Postgres:      "Docker container 0123456789ab on 127.0.0.1:5432",
		Warnings:      opts.warnings(),
	})
	t.Log("\n" + banner)

	for _, want := range []string{
		"DEVELOPMENT",
		"multitenant",
		"https://0.0.0.0:8443",
		"http://0.0.0.0:8080",
		rt.Issuer.Issuer(),
		rt.Issuer.TokenURL(),
		"provisioner",
		dir,
		"v1 API: disabled (503)",
		"lamassu_app",
		"-listen 0.0.0.0",
		bannerReadyLine,
	} {
		if !strings.Contains(banner, want) {
			t.Errorf("el banner no contiene %q", want)
		}
	}

	if strings.Contains(banner, "PRIVATE KEY") {
		t.Error("el banner contiene una clave privada")
	}
	// Ninguna línea de ninguna clave generada aparece en el banner.
	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".key") {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, line := range strings.Split(string(raw), "\n") {
			if len(line) > 20 && strings.Contains(banner, line) {
				t.Errorf("el banner contiene una línea de %s", path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeBannerWithV1AndWithoutLocalIssuer(t *testing.T) {
	sunset := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	banner := renderBanner(bannerInfo{
		RuntimeDir:    "/tmp/x",
		ListenAddress: "127.0.0.1",
		HTTPSPort:     8443,
		HTTPPort:      8080,
		V1:            monoconfig.V1Config{DefaultTenantID: "00000000-0000-0000-0000-000000000002", SunsetAt: sunset},
		Postgres:      "external",
	})
	for _, want := range []string{"local token issuer: disabled", "no tenant provisioner", "00000000-0000-0000-0000-000000000002", sunset.Format(time.RFC3339)} {
		if !strings.Contains(banner, want) {
			t.Errorf("el banner no contiene %q:\n%s", want, banner)
		}
	}
}
