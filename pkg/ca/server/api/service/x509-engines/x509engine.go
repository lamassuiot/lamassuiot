package x509engines

import (
	"crypto/x509"
	"time"

	"github.com/lamassuiot/lamassuiot/pkg/ca/common/api"
)

type X509Engine interface {
	GetEngineConfig() api.EngineProviderInfo
	CreateCA(input api.CreateCAInput) (*x509.Certificate, error)
	SignCertificateRequest(caCertificate *x509.Certificate, certificateExpiration time.Time, input *api.SignCertificateRequestInput) (*x509.Certificate, error)
	Sign(ca api.Certificate, message []byte, messageType string, signing_algorithm string) ([]byte, error)
	Verify(ca api.Certificate, signature []byte, message []byte, messageType string, signing_algorithm string) (bool, error)
	ImportCA(input api.PrivateKey, caName string) error
}
