package crypto

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
)

const (
	CSRPEMBlockType  = "CERTIFICATE REQUEST"
	PublicKeyHeader  = "-----BEGIN PUBLIC KEY-----"
	PublicKeyFooter  = "-----END PUBLIC KEY-----"
	CertPEMBlockType = "CERTIFICATE"
	KeyPEMBlockType  = "RSA PRIVATE KEY"
)

func ParseKeycloakPublicKey(data []byte) (*rsa.PublicKey, error) {
	pubPem, _ := pem.Decode(data)
	parsedKey, err := x509.ParsePKIXPublicKey(pubPem.Bytes)
	if err != nil {
		return nil, errors.New("Unable to parse public key")
	}
	pubKey := parsedKey.(*rsa.PublicKey)
	return pubKey, nil
}

func ParseNewCSR(data []byte) (*x509.CertificateRequest, error) {
	pemBlock, _ := pem.Decode(data)
	err := CheckPEMBlock(pemBlock, CSRPEMBlockType)
	if err != nil {
		return nil, err
	}
	certReq, err := x509.ParseCertificateRequest(pemBlock.Bytes)
	if err != nil {
		return nil, err
	}
	return certReq, nil
}

func CheckPEMBlock(pemBlock *pem.Block, blockType string) error {
	if pemBlock == nil {
		return errors.New("cannot find the next PEM formatted block")
	}
	if pemBlock.Type != blockType || len(pemBlock.Headers) != 0 {
		return errors.New("unmatched type of headers")
	}
	return nil
}

func CreateCAPool(CAPath string) (*x509.CertPool, error) {
	caCert, err := ioutil.ReadFile(CAPath)
	if err != nil {
		return nil, err
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	return caCertPool, nil
}
