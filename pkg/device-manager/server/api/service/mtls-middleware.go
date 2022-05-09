package service

import (
	"crypto/x509"

	"github.com/go-kit/kit/endpoint"
)

func NewParserm(mtlsCa x509.Certificate) endpoint.Middleware {
	return nil
}
