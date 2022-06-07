package store

import (
	"context"

	"github.com/lamassuiot/lamassuiot/pkg/ca/server/models/ca"
	"github.com/lamassuiot/lamassuiot/pkg/utils/server/filters"
)

type DB interface {
	InsertCert(ctx context.Context, caName string, serialNumber string) error
	SelectCertsByCA(ctx context.Context, caName string, queryParameters filters.QueryParameters) ([]ca.IssuedCerts, int, error)
	InsertCa(ctx context.Context, caName string, caType string) error
	SelectCas(ctx context.Context, caType string, queryParameters filters.QueryParameters) ([]ca.Cas, int, error)
	DeleteCa(ctx context.Context, caName string) error
}
