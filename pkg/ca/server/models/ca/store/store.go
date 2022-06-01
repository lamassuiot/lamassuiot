package store

import (
	"context"

	"github.com/lamassuiot/lamassuiot/pkg/ca/server/models/ca"
	"github.com/lamassuiot/lamassuiot/pkg/utils/server/filters"
)

type DB interface {
	InsertCert(ctx context.Context, caName string, serialNumber string) error
	SelectCertsByCA(ctx context.Context, caName string, queryParameters filters.QueryParameters) ([]ca.IssuedCerts, int, error)
}
