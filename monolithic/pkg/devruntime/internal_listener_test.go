package devruntime

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/monolithic/v3/pkg/devpki"
	"github.com/lamassuiot/lamassuiot/monolithic/v3/pkg/devprofile"
	"github.com/lamassuiot/lamassuiot/monolithic/v3/pkg/monoconfig"
)

// Los puertos internos se reservan en loopback antes de montar los
// servicios (D7): los clientes SDK los necesitan antes de que el destino
// arranque.
func TestInternalPortsAreReservedDistinctAndFree(t *testing.T) {
	rt, err := Start(Options{Dir: t.TempDir(), DevIssuer: true})
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	seen := map[int]monoconfig.Service{}
	for _, svc := range monoconfig.AllServices {
		port := rt.Multitenant.InternalTLS.Ports[svc]
		if port <= 0 {
			t.Fatalf("%s: puerto interno %d, se esperaba uno reservado", svc, port)
		}
		if other, dup := seen[port]; dup {
			t.Fatalf("%s y %s comparten el puerto interno %d", svc, other, port)
		}
		seen[port] = svc
		l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			t.Fatalf("%s: el puerto reservado %d no está libre: %v", svc, port, err)
		}
		l.Close()
	}
}

// El listener interno de un servicio configurado por devprofile acepta el
// certificado de otro servicio (CA interna) y rechaza el de otra CA, el de la
// CA del emisor local y la conexión sin certificado (requisitos 7.1 y 7.3).
func TestInternalListenerAcceptsOnlyTheInternalCA(t *testing.T) {
	rt, err := Start(Options{Dir: t.TempDir(), DevIssuer: true})
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	profile, err := devprofile.Build(monoconfig.MonolithicConfig{Multitenant: rt.Multitenant})
	if err != nil {
		t.Fatal(err)
	}
	server := profile.CA.Server
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	logger := chelpers.SetupLogger(cconfig.Info, "test", "internal listener")
	_, shutdown, err := routes.RunHttpRouterWithShutdown(logger, handler, server, models.APIServiceInfo{})
	if err != nil {
		t.Fatalf("no arranca el servidor con la config de devprofile: %v", err)
	}
	defer shutdown()
	url := fmt.Sprintf("https://127.0.0.1:%d/probe", rt.Multitenant.InternalTLS.Ports[monoconfig.ServiceCA])

	client := func(certs ...tls.Certificate) *http.Client {
		return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs: rt.InternalCA.Pool(), Certificates: certs,
		}}}
	}
	vaFiles := rt.Multitenant.InternalTLS.Services[monoconfig.ServiceVA]
	vaCert, err := tls.LoadX509KeyPair(vaFiles.CertFile, vaFiles.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client(vaCert).Get(url)
	if err != nil {
		t.Fatalf("el certificado interno de VA no entra: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("estado %d con el certificado interno de VA", resp.StatusCode)
	}

	otherCA, err := devpki.NewCA("other CA")
	if err != nil {
		t.Fatal(err)
	}
	other, err := otherCA.Issue("lamassu-va")
	if err != nil {
		t.Fatal(err)
	}
	monolithLeaf, err := rt.CA.Issue("lamassu-va")
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]*http.Client{
		"otra CA":         client(other.TLS),
		"CA del emisor":   client(monolithLeaf.TLS),
		"sin certificado": client(),
	} {
		if resp, err := c.Get(url); err == nil {
			resp.Body.Close()
			t.Errorf("%s: el listener interno aceptó la conexión (estado %d)", name, resp.StatusCode)
		}
	}
}
