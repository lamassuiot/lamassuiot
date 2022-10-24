package api

import (
	"crypto/x509"
)

type GetCasOutput struct {
	Certs []*x509.Certificate
}

type EnrollInput struct {
	Csr *x509.CertificateRequest `validate:"required"`
	Aps string                   `validate:"required"`
	Crt *x509.Certificate        `validate:"required"`
}
type EnrollOutput struct {
	Cert   *x509.Certificate
	CaCert *x509.Certificate
}
type ReenrollInput struct {
	Csr *x509.CertificateRequest `validate:"required"`
	Crt *x509.Certificate        `validate:"required"`
}

type ReenrollOutput struct {
	Cert   *x509.Certificate
	CaCert *x509.Certificate
}

type ServerKeyGenInput struct {
	Csr *x509.CertificateRequest `validate:"required"`
	Aps string                   `validate:"required"`
	Crt *x509.Certificate        `validate:"required"`
}
type ServerKeyGenOutput struct {
	Cert   *x509.Certificate
	Key    interface{}
	CaCert *x509.Certificate
}
