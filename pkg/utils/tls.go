package utils

import (
	"crypto/x509"
	"io/ioutil"
)

const (
	PublicKeyHeader = "-----BEGIN PUBLIC KEY-----"
	PublicKeyFooter = "-----END PUBLIC KEY-----"
)

func CreateCAPool(CAPath string) (*x509.CertPool, error) {
	caCert, err := ioutil.ReadFile(CAPath)
	if err != nil {
		return nil, err
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	return caCertPool, nil
}
