package devpki

import (
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestIssuedCertificateVerifiesOnlyAgainstItsCA(t *testing.T) {
	ca, err := NewCA("monolith CA")
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewCA("other CA")
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.Issue("kms")
	if err != nil {
		t.Fatal(err)
	}
	cert := leaf.TLS.Leaf
	if cert == nil {
		cert, err = x509.ParseCertificate(leaf.TLS.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, usage := range []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth} {
		if _, err := cert.Verify(x509.VerifyOptions{Roots: ca.Pool(), KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
			t.Errorf("uso %v: no verifica contra su CA: %v", usage, err)
		}
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: other.Pool()}); err == nil {
		t.Error("verifica contra otra CA")
	}
	if err := cert.VerifyHostname("127.0.0.1"); err != nil {
		t.Error(err)
	}
	if !cert.IPAddresses[0].Equal(net.IPv4(127, 0, 0, 1)) || cert.Subject.CommonName != "kms" {
		t.Errorf("certificado inesperado: %v %v", cert.IPAddresses, cert.Subject)
	}
}

func TestWriteFileUses0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(path, []byte("secret")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("permisos %v, se esperaba 0600", info.Mode().Perm())
	}
}
