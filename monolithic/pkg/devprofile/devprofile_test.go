package devprofile

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/config"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/monolithic/v3/pkg/monoconfig"
)

// Issuer con puntos y mayúsculas: debe llegar exacto a la config (requisito 4.2).
const testIssuer = "https://Keycloak.Example.com:8443/realms/Lamassu.Dev"

func baseConfig() monoconfig.MonolithicConfig {
	services := map[monoconfig.Service]monoconfig.InternalTLSFiles{}
	ports := map[monoconfig.Service]int{}
	for i, svc := range monoconfig.AllServices {
		services[svc] = monoconfig.InternalTLSFiles{
			CertFile: "/run/lamassu/internal/" + string(svc) + ".crt",
			KeyFile:  "/run/lamassu/internal/" + string(svc) + ".key",
		}
		ports[svc] = 20000 + i
	}

	return monoconfig.MonolithicConfig{
		Logs:          cconfig.Logging{Level: cconfig.Debug},
		Storage:       cconfig.PluggableStorageEngine{Provider: cconfig.Postgres, Config: map[string]interface{}{"username": "lamassu_app"}},
		CryptoEngines: []cconfig.CryptoEngineConfig{{ID: "filesystem-1", Type: cconfig.FilesystemProvider}},
		VAStorageDir:  "/tmp/va",
		Domains:       []string{"localhost"},
		Multitenant: monoconfig.MultitenantConfig{
			ListenAddress: "127.0.0.1",
			Issuers: []cconfig.HttpServerJWTIssuer{
				{Issuer: testIssuer, JWKSURL: testIssuer + "/protocol/openid-connect/certs"},
			},
			Provisioners: []config.TenantManagerProvisioner{
				{Issuer: testIssuer, Subject: "provisioner"},
			},
			InternalTLS: monoconfig.InternalTLSConfig{
				CAFile:   "/run/lamassu/internal/ca.crt",
				Services: services,
				Ports:    ports,
			},
		},
	}
}

func mustBuild(t *testing.T, conf monoconfig.MonolithicConfig) *Profile {
	t.Helper()
	p, err := Build(conf)
	if err != nil {
		t.Fatalf("Build devolvió error: %v", err)
	}
	return p
}

func TestBuildReturnsTheSevenServices(t *testing.T) {
	servers := mustBuild(t, baseConfig()).Servers()
	if len(servers) != 7 {
		t.Fatalf("se esperaban 7 servidores, hay %d", len(servers))
	}
	for _, svc := range monoconfig.AllServices {
		if _, ok := servers[svc]; !ok {
			t.Errorf("falta la config del servicio %s", svc)
		}
	}
}

func TestBuildEnablesJWTWithIssuerJWKSInEveryService(t *testing.T) {
	for svc, srv := range mustBuild(t, baseConfig()).Servers() {
		jwt := srv.Authentication.JWT
		if !jwt.Enabled {
			t.Errorf("%s: JWT desactivado", svc)
		}
		if jwt.Audience != DefaultAudience {
			t.Errorf("%s: audiencia %q, se esperaba %q", svc, jwt.Audience, DefaultAudience)
		}
		if len(jwt.IssuerJWKS) != 1 || jwt.IssuerJWKS[0].Issuer != testIssuer {
			t.Errorf("%s: issuer_jwks %+v no conserva el issuer exacto %q", svc, jwt.IssuerJWKS, testIssuer)
		}
		if len(jwt.IssuerJWKSURLs) != 0 {
			t.Errorf("%s: usa el formato obsoleto issuer_jwks_urls", svc)
		}
		if !reflect.DeepEqual(jwt.AllowedAlgorithms, []string{"RS256"}) {
			t.Errorf("%s: allowed_algorithms %v", svc, jwt.AllowedAlgorithms)
		}
		if jwt.JWKSCacheTTL <= 0 {
			t.Errorf("%s: jwks_cache_ttl %v", svc, jwt.JWKSCacheTTL)
		}
		issuers, deprecated, err := jwt.ResolveIssuerJWKS()
		if err != nil || deprecated || issuers[testIssuer] == "" {
			t.Errorf("%s: ResolveIssuerJWKS = %v, %v, %v", svc, issuers, deprecated, err)
		}
	}
}

func TestBuildKeepsCustomAudience(t *testing.T) {
	conf := baseConfig()
	conf.Multitenant.Audience = "lamassu"
	for svc, srv := range mustBuild(t, conf).Servers() {
		if srv.Authentication.JWT.Audience != "lamassu" {
			t.Errorf("%s: audiencia %q", svc, srv.Authentication.JWT.Audience)
		}
	}
}

func TestBuildEnablesTenantRateLimitWithChartDefaults(t *testing.T) {
	want := cconfig.HttpServerTenantRateLimit{Enabled: true, RequestsPerSecond: 100, Burst: 200}
	for svc, srv := range mustBuild(t, baseConfig()).Servers() {
		if srv.TenantRateLimit != want {
			t.Errorf("%s: tenant_rate_limit %+v, se esperaba %+v", svc, srv.TenantRateLimit, want)
		}
	}
}

func TestBuildLeavesVersioningEmptyByDefault(t *testing.T) {
	for svc, srv := range mustBuild(t, baseConfig()).Servers() {
		if srv.Versioning != (cconfig.HttpServerVersioning{}) {
			t.Errorf("%s: versioning %+v, se esperaba vacío (v1 → 503)", svc, srv.Versioning)
		}
	}
}

func TestBuildRejectsOnlyOneV1Value(t *testing.T) {
	onlyTenant := baseConfig()
	onlyTenant.Multitenant.V1.DefaultTenantID = "00000000-0000-0000-0000-000000000002"
	if _, err := Build(onlyTenant); err == nil || !strings.Contains(err.Error(), "sunset") {
		t.Errorf("solo tenant de v1: error %v, se esperaba uno que nombre la fecha de retirada", err)
	}

	onlySunset := baseConfig()
	onlySunset.Multitenant.V1.SunsetAt = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, err := Build(onlySunset); err == nil || !strings.Contains(err.Error(), "tenant") {
		t.Errorf("solo fecha de v1: error %v, se esperaba uno que nombre el tenant", err)
	}
}

func TestBuildFillsVersioningWhenBothV1ValuesAreGiven(t *testing.T) {
	conf := baseConfig()
	sunset := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	conf.Multitenant.V1 = monoconfig.V1Config{DefaultTenantID: "00000000-0000-0000-0000-000000000002", SunsetAt: sunset}
	want := cconfig.HttpServerVersioning{V1DefaultTenantID: "00000000-0000-0000-0000-000000000002", V1SunsetAt: sunset}
	for svc, srv := range mustBuild(t, conf).Servers() {
		if srv.Versioning != want {
			t.Errorf("%s: versioning %+v, se esperaba %+v", svc, srv.Versioning, want)
		}
	}
}

func TestBuildConfiguresCompleteInternalListener(t *testing.T) {
	conf := baseConfig()
	for svc, srv := range mustBuild(t, conf).Servers() {
		il := srv.InternalListener
		files := conf.Multitenant.InternalTLS.Services[svc]
		want := cconfig.HttpServerInternalListener{
			Enabled:      true,
			Port:         conf.Multitenant.InternalTLS.Ports[svc],
			CertFile:     files.CertFile,
			KeyFile:      files.KeyFile,
			ClientCAFile: conf.Multitenant.InternalTLS.CAFile,
		}
		if il != want {
			t.Errorf("%s: internal_listener %+v, se esperaba %+v", svc, il, want)
		}
	}
}

func TestBuildRejectsIncompleteInternalTLS(t *testing.T) {
	noCA := baseConfig()
	noCA.Multitenant.InternalTLS.CAFile = ""
	if _, err := Build(noCA); err == nil {
		t.Error("sin CA interna: se esperaba error")
	}

	noCert := baseConfig()
	delete(noCert.Multitenant.InternalTLS.Services, monoconfig.ServiceVA)
	if _, err := Build(noCert); err == nil || !strings.Contains(err.Error(), string(monoconfig.ServiceVA)) {
		t.Errorf("sin certificado interno de VA: error %v, se esperaba uno que nombre el servicio", err)
	}
}

func TestBuildUsesTheGivenListenAddress(t *testing.T) {
	conf := baseConfig()
	conf.Multitenant.ListenAddress = "10.1.2.3"
	for svc, srv := range mustBuild(t, conf).Servers() {
		if srv.ListenAddress != "10.1.2.3" {
			t.Errorf("%s: listen_address %q", svc, srv.ListenAddress)
		}
	}
}

func TestBuildDefaultsListenAddressToLoopback(t *testing.T) {
	conf := baseConfig()
	conf.Multitenant.ListenAddress = ""
	for svc, srv := range mustBuild(t, conf).Servers() {
		if srv.ListenAddress != "127.0.0.1" {
			t.Errorf("%s: listen_address %q, se esperaba 127.0.0.1", svc, srv.ListenAddress)
		}
	}
}

func TestBuildPassesProvisionersToTenantManager(t *testing.T) {
	conf := baseConfig()
	conf.Multitenant.Provisioners = append(conf.Multitenant.Provisioners, config.TenantManagerProvisioner{Issuer: "https://idp.example.com", Subject: "ops"})
	p := mustBuild(t, conf)
	if !reflect.DeepEqual(p.TenantManager.Provisioners, conf.Multitenant.Provisioners) {
		t.Errorf("provisioners %+v, se esperaba %+v", p.TenantManager.Provisioners, conf.Multitenant.Provisioners)
	}
}

func TestBuildRejectsMissingIssuersInsteadOfDisablingJWT(t *testing.T) {
	conf := baseConfig()
	conf.Multitenant.Issuers = nil
	if _, err := Build(conf); err == nil {
		t.Error("sin issuers: se esperaba error, no una config con JWT desactivado")
	}
}

func TestBuildRejectsNonHTTPSJWKS(t *testing.T) {
	conf := baseConfig()
	conf.Multitenant.Issuers = []cconfig.HttpServerJWTIssuer{{Issuer: "http://idp", JWKSURL: "http://idp/jwks"}}
	if _, err := Build(conf); err == nil || !strings.Contains(err.Error(), "https") {
		t.Errorf("JWKS por http: error %v, se esperaba uno que exija https", err)
	}
}

// Requisito 4.6: no hay ninguna entrada que desactive la autenticación JWT.
func TestMultitenantConfigHasNoOptionToDisableJWT(t *testing.T) {
	var walk func(t reflect.Type, path string)
	walk = func(typ reflect.Type, path string) {
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			name := strings.ToLower(f.Name)
			if f.Type.Kind() == reflect.Bool && (strings.Contains(name, "auth") || strings.Contains(name, "jwt")) {
				t.Errorf("%s.%s permite desactivar la autenticación", path, f.Name)
			}
			if f.Type.Kind() == reflect.Struct && f.Type.PkgPath() == typ.PkgPath() {
				walk(f.Type, path+"."+f.Name)
			}
		}
	}
	walk(reflect.TypeOf(monoconfig.MultitenantConfig{}), "MultitenantConfig")
}

func TestBuildConfiguresInternalSDKClientsWithMTLS(t *testing.T) {
	conf := baseConfig()
	p := mustBuild(t, conf)
	in := conf.Multitenant.InternalTLS

	check := func(name string, got cconfig.HTTPClient, caller, target monoconfig.Service) {
		t.Helper()
		want := cconfig.HTTPClient{
			LogLevel: cconfig.Info,
			AuthMode: cconfig.MTLS,
			AuthMTLSOptions: cconfig.AuthMTLSOptions{
				CertFile: in.Services[caller].CertFile,
				KeyFile:  in.Services[caller].KeyFile,
			},
			HTTPConnection: cconfig.HTTPConnection{
				Protocol: cconfig.HTTPS,
				BasicConnection: cconfig.BasicConnection{
					Hostname:  "127.0.0.1",
					Port:      in.Ports[target],
					TLSConfig: cconfig.TLSConfig{CACertificateFile: in.CAFile},
				},
			},
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: cliente %+v, se esperaba %+v", name, got, want)
		}
	}

	check("CA → KMS", p.CA.KMSClient.HTTPClient, monoconfig.ServiceCA, monoconfig.ServiceKMS)
	check("VA → CA", p.VA.CAClient.HTTPClient, monoconfig.ServiceVA, monoconfig.ServiceCA)
	check("VA → KMS", p.VA.KMSClient.HTTPClient, monoconfig.ServiceVA, monoconfig.ServiceKMS)
	check("Device Manager → CA", p.DeviceManager.CAClient.HTTPClient, monoconfig.ServiceDeviceManager, monoconfig.ServiceCA)
	check("DMS → CA", p.DMS.CAClient.HTTPClient, monoconfig.ServiceDMSManager, monoconfig.ServiceCA)
	check("DMS → Device Manager", p.DMS.DevManagerClient.HTTPClient, monoconfig.ServiceDMSManager, monoconfig.ServiceDeviceManager)
}

func TestBuildKeepsSharedSettingsFromMonolithicConfig(t *testing.T) {
	conf := baseConfig()
	p := mustBuild(t, conf)
	for svc, storage := range map[monoconfig.Service]cconfig.PluggableStorageEngine{
		monoconfig.ServiceKMS:           p.KMS.Storage,
		monoconfig.ServiceCA:            p.CA.Storage,
		monoconfig.ServiceVA:            p.VA.Storage,
		monoconfig.ServiceDeviceManager: p.DeviceManager.Storage,
		monoconfig.ServiceDMSManager:    p.DMS.Storage,
		monoconfig.ServiceAlerts:        p.Alerts.Storage,
		monoconfig.ServiceTenantManager: p.TenantManager.Storage,
	} {
		if !reflect.DeepEqual(storage, conf.Storage) {
			t.Errorf("%s: storage %+v, se esperaba %+v", svc, storage, conf.Storage)
		}
	}
	if p.KMS.CryptoEngineConfig.DefaultEngine != "filesystem-1" {
		t.Errorf("KMS: motor por defecto %q", p.KMS.CryptoEngineConfig.DefaultEngine)
	}
	if p.VA.FilesystemStorage.Config["storage_directory"] != "/tmp/va" {
		t.Errorf("VA: directorio %v", p.VA.FilesystemStorage.Config)
	}
}
