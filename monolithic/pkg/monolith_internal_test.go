package pkg

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	core "github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/monolithic/v3/pkg/devpki"
	"github.com/lamassuiot/lamassuiot/monolithic/v3/pkg/monoconfig"
	"github.com/lamassuiot/lamassuiot/sdk/v3"
)

// tenantContext construye el contexto que el SDK usa para elegir la ruta v2
// del tenant; la autorización real la hace el servicio con el JWT.
func tenantContext(orgID, tenantID, actor string) context.Context {
	return core.WithTenantContext(context.Background(), core.TenantContext{
		OrganizationID: orgID,
		TenantID:       tenantID,
		ActorID:        actor,
		ActorType:      "HUMAN",
		CorrelationID:  uuid.NewString(),
		Source:         "monolith-test",
		Validated:      true,
	})
}

// caClient es el SDK de CA con el token de subject, contra el puerto público
// de CA (sin prefijo). El SDK solo promueve a v2 las rutas /v1/... cuando la
// URL base no tiene ruta, así que a través del proxy (/api/ca/v1/...) no las
// reescribe; los servicios se llaman entre sí igual, sin prefijo.
func (m *testMonolith) caClient(t *testing.T, subject string) services.CAService {
	t.Helper()
	token := m.token(t, subject)
	cli := sdk.HttpClientWithCustomHeaders(&http.Client{
		Timeout:   30 * time.Second,
		Transport: http.DefaultTransport.(*http.Transport).Clone(),
	}, "Authorization", "Bearer "+token)
	return sdk.NewHttpCAClient(cli, fmt.Sprintf("http://127.0.0.1:%d", m.proxyRoutes["/api/ca/"]))
}

// createCA crea un perfil y una CA raíz en el tenant con el SDK. Crear la CA
// obliga a CA a llamar a KMS por el listener interno.
func (m *testMonolith) createCA(t *testing.T, orgID, tenantID, subject, commonName string) *models.CACertificate {
	t.Helper()
	ctx := tenantContext(orgID, tenantID, subject)
	cli := m.caClient(t, subject)
	profile, err := cli.CreateIssuanceProfile(ctx, services.CreateIssuanceProfileInput{
		Profile: models.IssuanceProfile{Name: "profile " + commonName, Validity: models.Validity{Type: models.Duration, Duration: models.TimeDuration(12 * time.Hour)}},
	})
	if err != nil {
		t.Fatalf("perfil en %s: %v", tenantID, err)
	}
	ca, err := cli.CreateCA(ctx, services.CreateCAInput{
		KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.ECDSA), Bits: 256},
		Subject:      models.Subject{CommonName: commonName},
		CAExpiration: models.Validity{Type: models.Duration, Duration: models.TimeDuration(24 * time.Hour)},
		ProfileID:    profile.ID,
	})
	if err != nil {
		t.Fatalf("CA en %s: %v", tenantID, err)
	}
	return ca
}

// TestMonolithInternalCalls recorre la tarea 9 de la spec 009 (requisitos
// 7.1–7.4): llamadas entre servicios por los listeners internos con mTLS.
func TestMonolithInternalCalls(t *testing.T) {
	m := startMonolith(t, "default", nil)
	issuer := m.rt.Issuer.Issuer()
	m.pg.seedMembership(t, testOrgA, testTenantA, issuer, "alice", "pki_admin")
	m.pg.seedMembership(t, testOrgB, testTenantB, issuer, "bob", "pki_admin")

	var ca *models.CACertificate
	t.Run("CACallsKMSInternallyToCreateACAInA", func(t *testing.T) {
		ca = m.createCA(t, testOrgA, testTenantA, "alice", "Internal calls CA A")
	})
	if ca == nil {
		t.Fatal("sin CA en A no se puede seguir")
	}
	ski := ca.Certificate.SubjectKeyID

	// El evento «CA creada» hace que VA pida la CA a CA y firme la CRL con
	// KMS, ambos por el listener interno, como INTERNAL_SERVICE en A.
	t.Run("VAServesCRLOfACAInA", func(t *testing.T) {
		path := "/api/va/tenants/" + testTenantA + "/crl/" + ski
		var resp testResponse
		deadline := time.Now().Add(60 * time.Second)
		for {
			resp = m.do(t, http.MethodGet, path, "", "", nil)
			if resp.status == http.StatusOK || time.Now().After(deadline) {
				break
			}
			time.Sleep(time.Second)
		}
		if resp.status != http.StatusOK {
			t.Fatalf("GET %s: estado %d, se esperaba 200; cuerpo: %.300s", path, resp.status, resp.body)
		}
		crl, err := x509.ParseRevocationList([]byte(resp.body))
		if err != nil {
			t.Fatalf("la respuesta no es una CRL DER: %v", err)
		}
		if err := crl.CheckSignatureFrom((*x509.Certificate)(ca.Certificate.Certificate)); err != nil {
			t.Fatalf("la CRL no la firma la CA de A: %v", err)
		}
	})

	t.Run("SameSKIThroughTenantBIs404", func(t *testing.T) {
		m.expect(t, http.StatusNotFound, http.MethodGet, "/api/va/tenants/"+testTenantB+"/crl/"+ski, "", "", nil)
	})

	t.Run("CAOfAIsNotVisibleFromB", func(t *testing.T) {
		_, err := m.caClient(t, "bob").GetCAByID(tenantContext(testOrgB, testTenantB, "bob"), services.GetCAByIDInput{CAID: ca.ID})
		if err == nil {
			t.Fatal("un pki_admin de B obtiene la CA de A")
		}
	})

	t.Run("InternalListenerRejectsClientsWithoutTheInternalCA", func(t *testing.T) {
		port := m.conf.Multitenant.InternalTLS.Ports[monoconfig.ServiceCA]
		url := fmt.Sprintf("https://127.0.0.1:%d/health", port)
		otherCA, err := devpki.NewCA("other CA")
		if err != nil {
			t.Fatal(err)
		}
		other, err := otherCA.Issue("lamassu-va")
		if err != nil {
			t.Fatal(err)
		}
		for name, certs := range map[string][]tls.Certificate{"sin certificado": nil, "otra CA": {other.TLS}} {
			c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
				RootCAs: m.rt.InternalCA.Pool(), Certificates: certs,
			}}}
			if resp, err := c.Get(url); err == nil {
				resp.Body.Close()
				t.Errorf("%s: el listener interno de CA aceptó la conexión (estado %d)", name, resp.StatusCode)
			}
		}
	})

	t.Run("ProxyDoesNotExposeInternalListeners", func(t *testing.T) {
		internal := map[int]monoconfig.Service{}
		for svc, port := range m.conf.Multitenant.InternalTLS.Ports {
			internal[port] = svc
		}
		if len(m.proxyRoutes) != len(monoconfig.AllServices) {
			t.Errorf("el proxy tiene %d rutas, se esperaban %d: %v", len(m.proxyRoutes), len(monoconfig.AllServices), m.proxyRoutes)
		}
		for prefix, port := range m.proxyRoutes {
			if svc, ok := internal[port]; ok {
				t.Errorf("la ruta %s del proxy apunta al listener interno de %s (%d)", prefix, svc, port)
			}
		}
	})
}
