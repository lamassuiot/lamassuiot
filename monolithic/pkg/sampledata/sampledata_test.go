package sampledata_test

// Pruebas con Docker de los datos de ejemplo (spec 009, tarea 11; requisitos
// 9.1–9.3): un PostgreSQL preparado como el del monolito y un monolito
// ensamblado en la prueba. TestMain borra solo el contenedor y el directorio
// propios, nunca por etiqueta.

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/monolithic/v3/pkg"
	"github.com/lamassuiot/lamassuiot/monolithic/v3/pkg/devissuer"
	"github.com/lamassuiot/lamassuiot/monolithic/v3/pkg/devruntime"
	"github.com/lamassuiot/lamassuiot/monolithic/v3/pkg/devstorage"
	"github.com/lamassuiot/lamassuiot/monolithic/v3/pkg/eventbus/inmemory"
	"github.com/lamassuiot/lamassuiot/monolithic/v3/pkg/sampledata"
)

var cleanups []func()

func TestMain(m *testing.M) {
	code := m.Run()
	for i := len(cleanups) - 1; i >= 0; i-- {
		cleanups[i]()
	}
	os.Exit(code)
}

type monolith struct {
	rt        *devruntime.Runtime
	routes    map[string]int
	httpsURL  string
	client    *http.Client
	cryptoDir string
}

var shared *monolith

// startMonolith lanza (una vez por proceso) PostgreSQL y un monolito
// multitenant con el emisor local, eventbus en memoria y crypto filesystem.
func startMonolith(t *testing.T) *monolith {
	t.Helper()
	if shared == nil {
		shared = launchMonolith(t, "")
	}
	return shared
}

// launchMonolith lanza un PostgreSQL propio y un monolito sobre él, como un
// arranque del binario. Con cryptoDir vacío usa un directorio crypto nuevo;
// si no, el indicado, que persiste entre arranques como /tmp/gotest.
func launchMonolith(t *testing.T, cryptoDir string) *monolith {
	t.Helper()
	ctx := context.Background()
	pgStarted, err := devstorage.Start(ctx, devstorage.StartOptions{StandardPort: false})
	if err != nil {
		t.Fatalf("no se pudo lanzar PostgreSQL (¿contención de Docker?): %v", err)
	}
	cleanups = append(cleanups, pgStarted.Cleanup)
	prepared, err := devstorage.Prepare(ctx, chelpers.SetupLogger(cconfig.Info, "Sample data test", "PostgreSQL"), pgStarted.Admin)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}

	dir, err := os.MkdirTemp("", "lamassu-sampledata-test-")
	if err != nil {
		t.Fatal(err)
	}
	cleanups = append(cleanups, func() { _ = os.RemoveAll(dir) })
	if cryptoDir == "" {
		cryptoDir = filepath.Join(dir, "crypto")
	}
	rt, err := devruntime.Start(devruntime.Options{Dir: filepath.Join(dir, "runtime"), DevIssuer: true})
	if err != nil {
		t.Fatalf("devruntime.Start: %v", err)
	}
	cleanups = append(cleanups, func() { _ = rt.Close() })

	inmemory.Register()
	bus := cconfig.EventBusEngine{LogLevel: cconfig.Info, Enabled: true, Provider: "inmemory", Config: map[string]interface{}{}}
	mt := rt.Multitenant
	mt.Provisioners = rt.DefaultProvisioners()
	assembled, err := pkg.AssembleMonolith(pkg.MonolithicConfig{
		Logs:                  cconfig.Logging{Level: cconfig.Info},
		PublisherEventBus:     bus,
		SubscriberEventBus:    bus,
		SubscriberDLQEventBus: bus,
		Storage:               prepared.Storage,
		CryptoEngines: []cconfig.CryptoEngineConfig{{
			ID:       "filesystem-test-1",
			Type:     cconfig.FilesystemProvider,
			Metadata: map[string]interface{}{},
			Config:   map[string]interface{}{"storage_directory": cryptoDir},
		}},
		Monitoring:   cconfig.MonitoringJob{Enabled: false, Frequency: "2m"},
		Domains:      []string{"localhost"},
		AssemblyMode: pkg.Http,
		VAStorageDir: filepath.Join(dir, "va"),
		Multitenant:  mt,
	})
	if err != nil {
		t.Fatalf("AssembleMonolith: %v", err)
	}
	return &monolith{
		rt:       rt,
		routes:   assembled.ProxyRoutes,
		httpsURL: fmt.Sprintf("https://127.0.0.1:%d", assembled.HTTPSPort),
		client: &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		},
		cryptoDir: cryptoDir,
	}
}

// options son las del arranque real: puertos directos de los servicios y
// tokens del emisor local.
func (m *monolith) options() sampledata.Options {
	return sampledata.Options{
		Targets: sampledata.TargetsFromProxyRoutes("127.0.0.1", m.routes),
		Issuer:  m.rt.Issuer.Issuer(),
		Tokens: func(req devissuer.TokenRequest) (string, error) {
			return m.rt.Issuer.Token(req)
		},
	}
}

func (m *monolith) get(t *testing.T, path, subject string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, m.httpsURL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	token, err := m.rt.Issuer.Token(devissuer.TokenRequest{Subject: subject, ActorType: "HUMAN"})
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := m.client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// TestPopulateSampleDataInDemoTenant: requisitos 9.1 y 9.2.
func TestPopulateSampleDataInDemoTenant(t *testing.T) {
	m := startMonolith(t)
	logger := chelpers.SetupLogger(cconfig.Info, "SampleData", "Test")

	result, err := sampledata.PopulateSampleData(context.Background(), logger, m.options())
	if err != nil {
		t.Fatalf("PopulateSampleData: %v", err)
	}
	if result.OrganizationID == "" || result.TenantID == "" {
		t.Fatalf("resultado sin organización o tenant: %+v", result)
	}
	if len(result.Warnings) > 0 {
		t.Errorf("avisos al crear los datos: %v", result.Warnings)
	}
	tenantPath := "/api/ca/api/v2/tenants/" + result.TenantID

	t.Run("DemoTenantHasCAs", func(t *testing.T) {
		status, body := m.get(t, tenantPath+"/cas", sampledata.SampleDataSubject)
		if status != http.StatusOK {
			t.Fatalf("GET cas: %d %.300s", status, body)
		}
		for _, id := range []string{"sample-generated-root-ca", "sample-imported-root-ca"} {
			if !strings.Contains(body, id) {
				t.Errorf("la CA %s no está en el tenant Demo: %.500s", id, body)
			}
		}
	})

	t.Run("DemoTenantHasDevices", func(t *testing.T) {
		status, body := m.get(t, "/api/devmanager/api/v2/tenants/"+result.TenantID+"/devices?page_size=100", sampledata.SampleDataSubject)
		if status != http.StatusOK {
			t.Fatalf("GET devices: %d %.300s", status, body)
		}
		var list struct {
			List []struct {
				ID string `json:"id"`
			} `json:"list"`
		}
		if err := json.Unmarshal([]byte(body), &list); err != nil {
			t.Fatalf("respuesta no JSON: %v", err)
		}
		if len(list.List) < 10 {
			t.Errorf("el tenant Demo tiene %d dispositivos, se esperaban al menos 10", len(list.List))
		}
	})

	t.Run("DemoAdminsAreLocalIdentities", func(t *testing.T) {
		status, body := m.get(t, "/api/tenants/api/v2/me/memberships", sampledata.DemoAdminSubject)
		if status != http.StatusOK || !strings.Contains(body, result.TenantID) || !strings.Contains(body, "tenant_admin") {
			t.Errorf("memberships de %s: %d %.300s", sampledata.DemoAdminSubject, status, body)
		}
		status, body = m.get(t, "/api/tenants/api/v2/me/memberships", sampledata.SampleDataSubject)
		if status != http.StatusOK || !strings.Contains(body, result.TenantID) || !strings.Contains(body, "pki_admin") {
			t.Errorf("memberships de %s: %d %.300s", sampledata.SampleDataSubject, status, body)
		}
	})

	t.Run("IdentityWithoutMembershipIs403", func(t *testing.T) {
		status, body := m.get(t, tenantPath+"/cas", "mallory")
		if status != http.StatusForbidden {
			t.Errorf("mallory en el tenant Demo: %d, se esperaba 403: %.300s", status, body)
		}
	})

	t.Run("SecondRunReusesOrganizationAndTenant", func(t *testing.T) {
		again, err := sampledata.PopulateSampleData(context.Background(), logger, m.options())
		if err != nil {
			t.Fatalf("segunda ejecución: %v", err)
		}
		if again.OrganizationID != result.OrganizationID || again.TenantID != result.TenantID {
			t.Errorf("la segunda ejecución no reutiliza: %+v frente a %+v", again, result)
		}
		status, body := m.get(t, "/api/tenants/api/v2/provisioning/organizations", "provisioner")
		if status != http.StatusOK {
			t.Fatalf("GET organizations: %d %.300s", status, body)
		}
		if n := strings.Count(body, `"name":"`+sampledata.DemoOrganizationName+`"`); n != 1 {
			t.Errorf("hay %d organizaciones %q, se esperaba 1: %.500s", n, sampledata.DemoOrganizationName, body)
		}
	})
}

// TestPopulateSampleDataNamesTheFailedStep: requisito 9.3 (el monolito sigue
// en marcha: main solo avisa; aquí se comprueba que el aviso dice el paso).
func TestPopulateSampleDataNamesTheFailedStep(t *testing.T) {
	m := startMonolith(t)
	logger := chelpers.SetupLogger(cconfig.Info, "SampleData", "Test")

	opts := m.options()
	opts.Targets.TenantManager = "http://127.0.0.1:1"
	_, err := sampledata.PopulateSampleData(context.Background(), logger, opts)
	if err == nil || !strings.Contains(err.Error(), "demo organization") {
		t.Errorf("error sin el paso fallido: %v", err)
	}

	opts = m.options()
	opts.Tokens = func(devissuer.TokenRequest) (string, error) { return "", fmt.Errorf("issuer down") }
	_, err = sampledata.PopulateSampleData(context.Background(), logger, opts)
	if err == nil || !strings.Contains(err.Error(), "token") {
		t.Errorf("error sin el paso fallido: %v", err)
	}
}

// TestPopulateSampleDataOnSecondStartWithSameCryptoDir: requisitos 9.1 y 9.2
// en un segundo arranque en el mismo equipo. El binario guarda las claves del
// motor filesystem en /tmp/gotest, que no se borra: un arranque nuevo (con su
// PostgreSQL vacío) sobre el directorio crypto de uno anterior tiene que crear
// otra vez todos los datos de ejemplo, sin avisos.
func TestPopulateSampleDataOnSecondStartWithSameCryptoDir(t *testing.T) {
	first := startMonolith(t)
	logger := chelpers.SetupLogger(cconfig.Info, "SampleData", "Test")
	if _, err := sampledata.PopulateSampleData(context.Background(), logger, first.options()); err != nil {
		t.Fatalf("primer arranque: %v", err)
	}

	second := launchMonolith(t, first.cryptoDir)
	result, err := sampledata.PopulateSampleData(context.Background(), logger, second.options())
	if err != nil {
		t.Fatalf("segundo arranque: %v", err)
	}
	if len(result.Warnings) > 0 {
		t.Errorf("avisos en el segundo arranque: %v", result.Warnings)
	}
	status, body := second.get(t, "/api/ca/api/v2/tenants/"+result.TenantID+"/cas", sampledata.SampleDataSubject)
	if status != http.StatusOK {
		t.Fatalf("GET cas: %d %.300s", status, body)
	}
	for _, id := range []string{"sample-generated-root-ca", "sample-imported-root-ca"} {
		if !strings.Contains(body, id) {
			t.Errorf("la CA %s no está en el tenant Demo del segundo arranque: %.500s", id, body)
		}
	}
}
