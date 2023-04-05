package clients

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"

	"github.com/globalsign/est"
	"github.com/lamassuiot/lamassuiot/pkg/config"
	"github.com/lamassuiot/lamassuiot/pkg/helppers"
	"github.com/lamassuiot/lamassuiot/pkg/models"
	"github.com/lamassuiot/lamassuiot/pkg/services"
)

type ESTClientBuilder struct {
	HTTPClient       *config.HTTPClient
	ReverseProxyOpts *ReverseProxyOpts
	APS              string
}

type ReverseProxyOpts struct {
	ClietCertificate *x509.Certificate
}

type ESTClient struct {
	estClient *est.Client
}

func NewESTClient(cliBuilder ESTClientBuilder) (services.ESTService, error) {
	additionalHeaders := map[string]string{}

	estClient := &est.Client{
		AdditionalPathSegment: cliBuilder.APS,
		InsecureSkipVerify:    cliBuilder.HTTPClient.HTTPConnection.InsecureSkipVerify,
	}

	urlAddress := fmt.Sprintf("%s:%d", cliBuilder.HTTPClient.HTTPConnection.Hostname, cliBuilder.HTTPClient.HTTPConnection.Port)
	if cliBuilder.HTTPClient.HTTPConnection.BasePath != "" {
		urlAddress = urlAddress + cliBuilder.HTTPClient.HTTPConnection.BasePath
	}

	estClient.Host = urlAddress

	if cliBuilder.HTTPClient.HTTPConnection.CACertificateFile != "" {
		caCert, err := helppers.ReadCertificateFromFile(cliBuilder.HTTPClient.HTTPConnection.CACertificateFile)
		if err != nil {
			return nil, err
		}

		caPool := x509.NewCertPool()
		caPool.AddCert(caCert)
		estClient.ExplicitAnchor = caPool
	}

	switch cliBuilder.HTTPClient.AuthMode {
	case config.MTLS:
		authOptions := cliBuilder.HTTPClient.AuthMTLSOptions
		privKey, err := helppers.ReadPrivateKeyFromFile(authOptions.KeyFile)
		if err != nil {
			return nil, err
		}

		cert, err := helppers.ReadCertificateFromFile(authOptions.CertFile)
		if err != nil {
			return nil, err
		}

		estClient.PrivateKey = privKey
		estClient.Certificates = []*x509.Certificate{(*x509.Certificate)(cert)}
	}

	if cliBuilder.ReverseProxyOpts != nil {
		cert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cliBuilder.ReverseProxyOpts.ClietCertificate.Raw}))
		params := url.Values{}
		params.Add("Cert", cert)
		additionalHeaders["X-Forwarded-Client-Cert"] = params.Encode()
	}

	estClient.AdditionalHeaders = additionalHeaders
	estSvc := &ESTClient{estClient: estClient}
	return estSvc, nil
}

func (c *ESTClient) CACerts(ctx context.Context, aps string) ([]*x509.Certificate, error) {
	return nil, fmt.Errorf("TODO")
}

func (c *ESTClient) Enroll(ctx context.Context, authMode models.ESTAuthMode, csr *x509.CertificateRequest, aps string) (*x509.Certificate, error) {
	ogHeaders := c.estClient.AdditionalHeaders
	if headers := ctx.Value(models.ESTHeaders); headers != nil {
		if headersMap, ok := headers.(map[string]string); ok {
			newHeaders := helppers.MergeMaps(&c.estClient.AdditionalHeaders, &headersMap)
			c.estClient.AdditionalHeaders = *newHeaders
		}
	}

	signedCert, err := c.estClient.Enroll(ctx, csr)
	c.estClient.AdditionalHeaders = ogHeaders

	return signedCert, err
}

// Reenroll renews an existing certificate.
func (c *ESTClient) Reenroll(ctx context.Context, authMode models.ESTAuthMode, csr *x509.CertificateRequest, aps string) (*x509.Certificate, error) {
	return nil, fmt.Errorf("TODO")
}

func (c *ESTClient) ServerKeyGen(ctx context.Context, authMode models.ESTAuthMode, csr *x509.CertificateRequest, aps string) (*x509.Certificate, interface{}, error) {
	return nil, nil, fmt.Errorf("TODO")
}
