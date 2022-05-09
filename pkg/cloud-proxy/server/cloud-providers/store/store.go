package store

import (
	"context"
	"time"

	cloudproviders "github.com/lamassuiot/lamassuiot/pkg/cloud-proxy/server/cloud-providers"
)

type DB interface {
	InsertSynchronizedCA(ctx context.Context, connectorID string, caName string, enabledTs time.Time) error
	UpdateSynchronizedCA(ctx context.Context, connectorID string, caName string, caSerialNumber string) error
	SelectAllSynchronizedCAs(ctx context.Context) ([]cloudproviders.DatabaseSynchronizedCA, error)
	SelectSynchronizedCAsByConnectorID(ctx context.Context, connectorID string) ([]cloudproviders.DatabaseSynchronizedCA, error)
	SelectSynchronizedCAsByCaName(ctx context.Context, caName string) ([]cloudproviders.DatabaseSynchronizedCA, error)
	SelectSynchronizedCAsByConnectorIDAndConnectorID(ctx context.Context, caName string, connectorID string) (cloudproviders.DatabaseSynchronizedCA, error)
}
