package main

// Valores por defecto seguros y opciones incompatibles (spec 009, tarea 12;
// requisitos 10.1, 10.5; decisiones P4, P5 y P6).

import (
	"strings"
	"testing"
)

func TestListenDefaultsToLoopback(t *testing.T) {
	opts, err := parse(t)
	if err != nil {
		t.Fatal(err)
	}
	if opts.listen != "127.0.0.1" {
		t.Errorf("-listen por defecto %q, se esperaba 127.0.0.1", opts.listen)
	}
	if opts.httpsPort != 8443 || opts.httpPort != 8080 {
		t.Errorf("puertos del proxy por defecto %d/%d, se esperaban 8443/8080", opts.httpsPort, opts.httpPort)
	}
	if w := opts.warnings(); len(w) != 0 {
		t.Errorf("avisos con la configuración por defecto: %v", w)
	}
}

func TestListenOnAnotherInterfaceIsWarned(t *testing.T) {
	for _, addr := range []string{"0.0.0.0", "192.168.1.10", "::"} {
		opts, err := parse(t, "-listen", addr)
		if err != nil {
			t.Fatalf("-listen %s: %v", addr, err)
		}
		w := strings.Join(opts.warnings(), "\n")
		if !strings.Contains(w, addr) || !strings.Contains(w, "127.0.0.1") {
			t.Errorf("-listen %s: aviso %q, se esperaba uno que nombre la interfaz y diga que el emisor sigue en 127.0.0.1", addr, w)
		}
	}
	for _, addr := range []string{"::1", "127.0.0.1"} {
		opts, err := parse(t, "-listen", addr)
		if err != nil {
			t.Fatalf("-listen %s: %v", addr, err)
		}
		if w := opts.warnings(); len(w) != 0 {
			t.Errorf("-listen %s (loopback) avisa: %v", addr, w)
		}
	}
}

func TestListenRejectsWhatIsNotAnIPAddress(t *testing.T) {
	for _, addr := range []string{"", "localhost", "127.0.0.1:8443", "example.com"} {
		if _, err := parse(t, "-listen", addr); err == nil || !strings.Contains(err.Error(), "-listen") {
			t.Errorf("-listen %q: error %v, se esperaba uno que nombre -listen", addr, err)
		}
	}
}

func TestListenRejectsInvalidProxyPorts(t *testing.T) {
	for _, args := range [][]string{{"-https-port", "70000"}, {"-http-port", "-1"}, {"-https-port", "9000", "-http-port", "9000"}} {
		if _, err := parse(t, args...); err == nil {
			t.Errorf("%v aceptado", args)
		}
	}
	opts, err := parse(t, "-https-port", "0", "-http-port", "0")
	if err != nil {
		t.Fatalf("puertos 0 (aleatorios): %v", err)
	}
	if opts.httpsPort != 0 || opts.httpPort != 0 {
		t.Errorf("puertos %d/%d", opts.httpsPort, opts.httpPort)
	}
}

func TestDefaultsRejectAWSIoT(t *testing.T) {
	_, err := parse(t, "-awsiot")
	if err == nil || !strings.Contains(err.Error(), "-awsiot") || !strings.Contains(err.Error(), "tenant") {
		t.Errorf("error %v, se esperaba el rechazo de -awsiot en el perfil multitenant (P6)", err)
	}
}

func TestDefaultsDisableThePublishedUI(t *testing.T) {
	opts, err := parse(t)
	if err != nil {
		t.Fatal(err)
	}
	if !opts.disableUI {
		t.Error("la UI publicada está activa por defecto (P4)")
	}
	_, err = parse(t, "-disable-ui=false")
	if err == nil || !strings.Contains(err.Error(), "-disable-ui") || !strings.Contains(err.Error(), "v1") {
		t.Errorf("error %v, se esperaba el rechazo de la UI publicada, que usa v1 (P4)", err)
	}
}
