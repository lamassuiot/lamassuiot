// Package devpki genera la CA efímera del monolito de desarrollo (spec 009) y
// los certificados que firma: el TLS del emisor local de tokens y, desde las
// tareas 7 y 9, los de los listeners internos de cada servicio. Las claves
// viven en memoria; solo se escriben a disco con WriteFile (0600).
package devpki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"

	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
)

// validity cubre de sobra una sesión de desarrollo; la CA muere con el proceso.
const validity = 90 * 24 * time.Hour

// CA es la CA del monolito. Solo existe en memoria.
type CA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
}

// Leaf es un certificado firmado por la CA, válido para 127.0.0.1 y
// localhost, con uso de servidor y de cliente.
type Leaf struct {
	CertPEM []byte
	KeyPEM  []byte
	TLS     tls.Certificate
}

// NewCA genera una CA nueva con una clave ECDSA P-256.
func NewCA(commonName string) (*CA, error) {
	if commonName == "" {
		return nil, errors.New("devpki: CA common name is required")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("devpki: generate CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"Lamassu development monolith"}},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(validity),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("devpki: create CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("devpki: parse CA certificate: %w", err)
	}
	return &CA{cert: cert, key: key, certPEM: []byte(chelpers.CertificateToPEM(cert))}, nil
}

// Certificate devuelve el certificado de la CA.
func (ca *CA) Certificate() *x509.Certificate { return ca.cert }

// CertPEM devuelve el certificado de la CA en PEM.
func (ca *CA) CertPEM() []byte { return append([]byte(nil), ca.certPEM...) }

// Pool devuelve un pool que solo contiene esta CA.
func (ca *CA) Pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	return pool
}

// Issue firma un certificado para commonName, válido para 127.0.0.1 y
// localhost.
func (ca *CA) Issue(commonName string) (*Leaf, error) {
	if commonName == "" {
		return nil, errors.New("devpki: certificate common name is required")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("devpki: generate key for %s: %w", commonName, err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, fmt.Errorf("devpki: sign certificate for %s: %w", commonName, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("devpki: parse certificate for %s: %w", commonName, err)
	}
	keyPEM, err := chelpers.PrivateKeyToPEM(key)
	if err != nil {
		return nil, fmt.Errorf("devpki: encode key for %s: %w", commonName, err)
	}
	certPEM := []byte(chelpers.CertificateToPEM(cert))
	pair, err := tls.X509KeyPair(certPEM, []byte(keyPEM))
	if err != nil {
		return nil, fmt.Errorf("devpki: build TLS pair for %s: %w", commonName, err)
	}
	return &Leaf{CertPEM: certPEM, KeyPEM: []byte(keyPEM), TLS: pair}, nil
}

// WriteFile escribe data en path con permisos 0600, aunque el fichero ya
// existiera con otros.
func WriteFile(path string, data []byte) error {
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

func randomSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, fmt.Errorf("devpki: generate serial: %w", err)
	}
	return serial.Add(serial, big.NewInt(1)), nil
}
