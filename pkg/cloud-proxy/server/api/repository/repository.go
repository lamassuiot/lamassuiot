package repository

import (
	"context"

	"github.com/lamassuiot/lamassuiot/pkg/cloud-proxy/common/api"
)

type CloudProxyRepository interface {
	InsertCABinding(ctx context.Context, connectorID string, caName string) error
	UpdateCABindingSerialNumber(ctx context.Context, connectorID string, caName string, caSerialNumber string) error
	SelectCABindingsByConnectorID(ctx context.Context, connectorID string) ([]api.CABinding, error)
	SelectCABindingByConnectorIDAndCAName(ctx context.Context, connectorID string, caName string) (api.CABinding, error)
}
