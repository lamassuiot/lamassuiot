package mtls

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io/ioutil"
	stdhttp "net/http"
	"net/url"
	"strings"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/transport/http"
	lamassuca "github.com/lamassuiot/lamassuiot/pkg/ca/client"
	caDTO "github.com/lamassuiot/lamassuiot/pkg/ca/common/dto"
	"github.com/lamassuiot/lamassuiot/pkg/utils/server/filters"
)

type contextKey string

const (
	PeerCertificatesContextKey contextKey = "PeerCertificatesContextKey"
	XForwardedCertifcate       contextKey = "XForwardedCertificate"
)

var (
	ErrPeerCertificatesContextMissing = errors.New("certificate up for parsing was not passed through the context")
)

func HTTPToContext() http.RequestFunc {
	return func(ctx context.Context, r *stdhttp.Request) context.Context {
		ClientCert := r.Header.Get("X-Forwarded-Client-Cert")
		if len(ClientCert) > 0 {
			splits := strings.Split(ClientCert, ";")
			Cert := splits[1]
			Cert = strings.Split(Cert, "=")[1]
			Cert = strings.Replace(Cert, "\"", "", -1)
			decodedCert, _ := url.QueryUnescape(Cert)
			block, _ := pem.Decode([]byte(decodedCert))
			certificate, _ := x509.ParseCertificate(block.Bytes)
			return context.WithValue(ctx, XForwardedCertifcate, certificate)
		} else if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			certificate := r.TLS.PeerCertificates[0]
			return context.WithValue(ctx, PeerCertificatesContextKey, certificate)
		} else {
			return ctx
		}
	}
}

func NewParser(enroll bool, mutualTLSClientCAFile string, lamassuCaClient lamassuca.LamassuCaClient, ctx context.Context) endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (response interface{}, err error) {
			XForCert, _ := ctx.Value(XForwardedCertifcate).(*x509.Certificate)
			peerCert, _ := ctx.Value(PeerCertificatesContextKey).(*x509.Certificate)
			if XForCert != nil {
				_ = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: XForCert.Raw})
				_, err = VerifyPeerCertificate(ctx, XForCert, enroll, lamassuCaClient, nil)
				if err != nil {
					return nil, err
				}
				return next(ctx, request)
			} else if peerCert != nil {
				certContent, err := ioutil.ReadFile(mutualTLSClientCAFile)
				if err != nil {
					return nil, err
				}
				cpb, _ := pem.Decode(certContent)
				crt, err := x509.ParseCertificate(cpb.Bytes)
				if err != nil {
					return nil, err
				}
				_, err = VerifyPeerCertificate(ctx, peerCert, enroll, lamassuCaClient, crt)
				if err != nil {
					return nil, err
				}
				return next(ctx, request)
			} else {
				return nil, ErrPeerCertificatesContextMissing
			}
		}
	}
}

func VerifyPeerCertificate(ctx context.Context, cert *x509.Certificate, enroll bool, lamassuCaClient lamassuca.LamassuCaClient, certCA *x509.Certificate) (string, error) {
	if certCA != nil {
		clientCAs := x509.NewCertPool()
		clientCAs.AddCert(certCA)

		opts := x509.VerifyOptions{
			Roots:     clientCAs,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		_, err := cert.Verify(opts)
		if err != nil {
			return "", err
		}
		return "", err
	}
	var certs caDTO.GetCasResponse
	if !enroll {
		caType, _ := caDTO.ParseCAType("pki")
		limit := 50
		i := 0
		for {
			cas, err := lamassuCaClient.GetCAs(ctx, caType, filters.QueryParameters{Pagination: filters.PaginationOptions{Limit: limit, Offset: i * limit}})
			if err != nil {
				return "", err
			}
			if len(cas.CAs) == 0 {
				break
			}
			certs.CAs = append(certs.CAs, cas.CAs...)
			i++
		}
	} else {
		caType, err := caDTO.ParseCAType("dmsenroller")
		certs, err = lamassuCaClient.GetCAs(ctx, caType, filters.QueryParameters{})
		if err != nil {
			return "", err
		}
	}
	CAsCertificates := []*x509.Certificate{}
	for _, v := range certs.CAs {
		data, _ := base64.StdEncoding.DecodeString(v.CertContent.CerificateBase64)
		block, _ := pem.Decode([]byte(data))
		certificate, _ := x509.ParseCertificate(block.Bytes)
		CAsCertificates = append(CAsCertificates, certificate)
	}
	clientCAs := x509.NewCertPool()
	for _, certificate := range CAsCertificates {
		clientCAs.AddCert(certificate)
	}

	opts := x509.VerifyOptions{
		Roots:     clientCAs,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	candidateCa, err := cert.Verify(opts)
	if err != nil {
		return "", err
	}
	CA := candidateCa[0][1]
	b := pem.Block{Type: "CERTIFICATE", Bytes: CA.Raw}
	var aps string
	for _, v := range certs.CAs {
		data, _ := base64.StdEncoding.DecodeString(v.CertContent.CerificateBase64)
		block, _ := pem.Decode([]byte(data))
		if bytes.Equal(block.Bytes, b.Bytes) {
			aps = v.Name

		}
	}
	return aps, err
}
