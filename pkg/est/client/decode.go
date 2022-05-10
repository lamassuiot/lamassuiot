package client

import (
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/lamassuiot/lamassuiot/pkg/utils"
	"go.mozilla.org/pkcs7"
)

func ReadAllBase64Response(r io.Reader) ([]byte, error) {
	b, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read HTTP response body: %w", err)
	}

	decoded, err := utils.DecodeB64(string(b))
	if err != nil {
		return nil, fmt.Errorf("failed to base64-decode HTTP response body: %w", err)
	}

	return []byte(decoded), nil
}

func DecodePKCS7CertsOnly(b []byte) ([]*x509.Certificate, error) {
	p7, err := pkcs7.Parse(b)
	if err != nil {
		return nil, err
	}
	return p7.Certificates, nil
}

func ReadCertResponse(r io.Reader) ([]*x509.Certificate, error) {
	p7, err := ReadAllBase64Response(r)
	if err != nil {
		return nil, err
	}

	certs, err := DecodePKCS7CertsOnly(p7)
	if err != nil {
		return nil, fmt.Errorf("failed to decode PKCS7: %w", err)
	}
	return certs, nil
}
