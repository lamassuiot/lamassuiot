package store

import (
	"context"
)

type DB interface {
	CountDevicesByDmsId(ctx context.Context, dmsId string) (int, error)
}
