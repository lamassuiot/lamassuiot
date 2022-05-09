package mtls

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	stdhttp "net/http"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/transport/http"
)

type contextKey string

const (
	PeerCertificatesContextKey contextKey = "PeerCertificatesContextKey"
)

var (
	ErrPeerCertificatesContextMissing = errors.New("token up for parsing was not passed through the context")
)

func HTTPToContext() http.RequestFunc {
	return func(ctx context.Context, r *stdhttp.Request) context.Context {
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			return context.WithValue(ctx, PeerCertificatesContextKey, r.TLS.PeerCertificates[0])
		} else {
			return ctx
		}
	}
}
func NewParser() endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (response interface{}, err error) {
			peerCert, ok := ctx.Value(PeerCertificatesContextKey).(*x509.Certificate)
			if !ok {
				return nil, ErrPeerCertificatesContextMissing
			}
			_ = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: peerCert.Raw})
			return next(ctx, request)
		}
	}
}
