package pkg

// Valores por defecto seguros del monolito ensamblado (spec 009, tarea 12;
// requisitos 1.4, 10.1 y 10.3; decisiones P5 y D9).

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
)

// nonLoopbackIP devuelve una IP de este equipo que no es loopback, o "" si
// no hay ninguna.
func nonLoopbackIP(t *testing.T) string {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
			return ipNet.IP.String()
		}
	}
	return ""
}

func dialable(address string) bool {
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// TestRuntimeDirIsRequired: sin directorio propio el ensamblador no escribe
// las claves del proxy en el directorio de trabajo (D9); falla antes de
// montar nada.
func TestRuntimeDirIsRequired(t *testing.T) {
	cwd, _ := os.Getwd()
	_, err := AssembleMonolith(MonolithicConfig{AssemblyMode: Http})
	if err == nil || !strings.Contains(err.Error(), "runtime directory") {
		t.Fatalf("error %v, se esperaba uno que pida el directorio propio", err)
	}
	for _, name := range []string{"proxy.crt", "proxy.key"} {
		if _, err := os.Stat(filepath.Join(cwd, name)); err == nil {
			t.Errorf("%s escrito en el directorio de trabajo", name)
		}
	}
}

func TestDefaultsProxyListensOnlyOnLoopback(t *testing.T) {
	m := startMonolith(t, "default", nil)
	port := strings.TrimPrefix(m.httpsURL, "https://127.0.0.1:")
	if !dialable("127.0.0.1:" + port) {
		t.Fatalf("el proxy no escucha en 127.0.0.1:%s", port)
	}
	ip := nonLoopbackIP(t)
	if ip == "" {
		t.Skip("este equipo no tiene ninguna IPv4 que no sea loopback")
	}
	if dialable(net.JoinHostPort(ip, port)) {
		t.Errorf("el proxy acepta conexiones en %s:%s (fuera de loopback)", ip, port)
	}
	for prefix, servicePort := range m.proxyRoutes {
		if dialable(net.JoinHostPort(ip, fmt.Sprint(servicePort))) {
			t.Errorf("el servicio %s acepta conexiones en %s:%d (fuera de loopback)", prefix, ip, servicePort)
		}
	}
}

func TestRuntimeProxyFilesArePrivate(t *testing.T) {
	m := startMonolith(t, "default", nil)
	for _, name := range []string{"proxy.crt", "proxy.key"} {
		info, err := os.Stat(filepath.Join(m.conf.Multitenant.RuntimeDir, name))
		if err != nil {
			t.Fatalf("%s no está en el directorio propio: %v", name, err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s: permisos %v, se esperaba 0600", name, info.Mode().Perm())
		}
	}
	cwd, _ := os.Getwd()
	for _, name := range []string{"proxy.crt", "proxy.key"} {
		if _, err := os.Stat(filepath.Join(cwd, name)); err == nil {
			t.Errorf("%s escrito en el directorio de trabajo", name)
		}
	}
}

// TestDefaultsAssemblyFailureNamesServiceAndLeavesNoProxy: requisito 1.4. Un
// motor criptográfico que no existe hace fallar el montaje de KMS.
func TestDefaultsAssemblyFailureNamesServiceAndLeavesNoProxy(t *testing.T) {
	base := startMonolith(t, "default", nil)
	httpsPort, httpPort := freePort(t), freePort(t)
	conf := base.conf
	dir := t.TempDir()
	conf.Multitenant.RuntimeDir = dir
	conf.GatewayPortHttps, conf.GatewayPortHttp = httpsPort, httpPort
	conf.CryptoEngines = []cconfig.CryptoEngineConfig{{ID: "broken", Type: "no-such-engine", Metadata: map[string]interface{}{}, Config: map[string]interface{}{}}}

	_, err := AssembleMonolith(conf)
	if err == nil || !strings.Contains(err.Error(), "KMS") {
		t.Fatalf("error %v, se esperaba uno que nombre KMS", err)
	}
	for _, port := range []int{httpsPort, httpPort} {
		if dialable(fmt.Sprintf("127.0.0.1:%d", port)) {
			t.Errorf("el proxy escucha en %d tras el fallo", port)
		}
	}
}
