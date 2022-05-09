package store

import (
	"context"

	"github.com/lamassuiot/lamassuiot/pkg/ca/common/dto"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/models/ca"
)

type DB interface {
	InsertCert(ctx context.Context, caName string, serialNumber string) error
	SelectCertsbyCA(ctx context.Context, caName string, queryParameters dto.QueryParameters) ([]ca.IssuedCerts, int, error)
}
