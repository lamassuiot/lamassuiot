package clients

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"

	"github.com/globalsign/est"
)

type ESTClientBuilder struct {
	URL                string
	InsecureSkipVerify bool
	APS                string
	PrivateKey         interface{}
	Certificate        *x509.Certificate
	CACertPool         *x509.CertPool
	UseReverseProxy    *ReverseProxyOpts
}

type ReverseProxyOpts struct {
	ClietCertificate *x509.Certificate
}

func NewESTClient(cliBuilder ESTClientBuilder) (*est.Client, error) {
	_, ecOK := cliBuilder.PrivateKey.(*ecdsa.PrivateKey)
	_, rsaOK := cliBuilder.PrivateKey.(*rsa.PrivateKey)
	if !(rsaOK || ecOK) {
		return nil, fmt.Errorf("key is not a rsa.PrivateKey or ecdsa.PrivateKey")
	}

	additionalHeaders := map[string]string{}
	if reverseProxy := cliBuilder.UseReverseProxy == nil; reverseProxy {
		cert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cliBuilder.UseReverseProxy.ClietCertificate.Raw}))
		params := url.Values{}
		params.Add("Cert", cert)
		additionalHeaders["X-Forwarded-Client-Cert"] = params.Encode()
	}

	return &est.Client{
		Host:                  cliBuilder.URL,
		InsecureSkipVerify:    cliBuilder.InsecureSkipVerify,
		AdditionalPathSegment: cliBuilder.APS,
		ExplicitAnchor:        cliBuilder.CACertPool,
		Certificates:          []*x509.Certificate{cliBuilder.Certificate},
		PrivateKey:            cliBuilder.PrivateKey,
		AdditionalHeaders:     additionalHeaders,
	}, nil

}
