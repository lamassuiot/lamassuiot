package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/url"

	"github.com/globalsign/est"
	"github.com/go-kit/log"
)

type ESTClientConfig struct {
	logger             log.Logger
	address            *url.URL
	certificate        []*x509.Certificate
	privateKey         interface{}
	caCertPool         *x509.CertPool
	insecureSkipVerify bool
}

type ESTContextKey string

var (
	WithXForwardedClientCertHeader ESTContextKey = "With-X-Forwarded-Client-Cert"
)

type ESTClient interface {
	CACerts(ctx context.Context) ([]*x509.Certificate, error)
	Enroll(ctx context.Context, aps string, csr *x509.CertificateRequest) (*x509.Certificate, error)
	Reenroll(ctx context.Context, csr *x509.CertificateRequest, aps string) (*x509.Certificate, error)
	ServerKeyGen(ctx context.Context, aps string, csr *x509.CertificateRequest) (*x509.Certificate, interface{}, error)
}

func NewESTClient(logger log.Logger, url *url.URL, clientCert []*x509.Certificate, key interface{}, caCertificate *x509.Certificate, insecureSkipVerify bool) (ESTClient, error) {
	_, ecOK := key.(*ecdsa.PrivateKey)
	_, rsaOK := key.(*rsa.PrivateKey)
	if !(rsaOK || ecOK) {
		return nil, errors.New("key is not a rsa.PrivateKey or ecdsa.PrivateKey")
	}

	caCertPool := x509.NewCertPool()
	if !insecureSkipVerify {
		if caCertificate == nil {
			return nil, errors.New("caCertificate is nil")
		}
		caCertPool.AddCert(caCertificate)
	}

	return &ESTClientConfig{
		logger:             logger,
		address:            url,
		caCertPool:         caCertPool,
		certificate:        clientCert,
		privateKey:         key,
		insecureSkipVerify: insecureSkipVerify,
	}, nil
}

func (c *ESTClientConfig) CACerts(ctx context.Context) ([]*x509.Certificate, error) {
	return c.makeESTClient(ctx, "").CACerts(ctx)
}

func (c *ESTClientConfig) Enroll(ctx context.Context, aps string, csr *x509.CertificateRequest) (*x509.Certificate, error) {
	return c.makeESTClient(ctx, aps).Enroll(ctx, csr)
}

func (c *ESTClientConfig) Reenroll(ctx context.Context, csr *x509.CertificateRequest, aps string) (*x509.Certificate, error) {
	return c.makeESTClient(ctx, aps).Reenroll(ctx, csr)
}

func (c *ESTClientConfig) ServerKeyGen(ctx context.Context, aps string, csr *x509.CertificateRequest) (*x509.Certificate, interface{}, error) {
	crt, keyBytes, err := c.makeESTClient(ctx, aps).ServerKeyGen(ctx, csr)
	if err != nil {
		return nil, nil, err
	}

	key, err := x509.ParsePKCS8PrivateKey(keyBytes)
	return crt, key, err
}

func (c *ESTClientConfig) makeESTClient(ctx context.Context, aps string) *est.Client {
	certs := c.certificate

	dmsName := ctx.Value("dmsName").(string)
	additionalHeaders := map[string]string{}

	if ctx != nil {
		if proxyCert, ok := ctx.Value(WithXForwardedClientCertHeader).(*x509.Certificate); ok {
			cert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: proxyCert.Raw}))
			params := url.Values{}
			params.Add("Cert", cert)
			additionalHeaders["X-Forwarded-Client-Cert"] = params.Encode()
		}
	}

	host := c.address.Host
	if c.address.Path != "" {
		host = host + "/" + c.address.Path
	}
	additionalHeaders["x-dms-name"] = dmsName

	return &est.Client{
		Host:                  host,
		AdditionalPathSegment: aps,
		Certificates:          certs,
		PrivateKey:            c.privateKey,
		ExplicitAnchor:        c.caCertPool,
		InsecureSkipVerify:    c.insecureSkipVerify,
		AdditionalHeaders:     additionalHeaders,
	}
}
