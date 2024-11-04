package services

import (
	"context"

	"golang.org/x/crypto/ocsp"
)

type OCSPService interface {
	Verify(ctx context.Context, req *ocsp.Request) ([]byte, error)
}
