package store

import (
	"context"

	"github.com/lamassuiot/lamassuiot/pkg/dms-enroller/server/models/dms"
)

type DB interface {
	SelectBySerialNumber(ctx context.Context, SerialNumber string) (string, error)
	SelectByDMSIDAuthorizedCAs(ctx context.Context, dmsid string) ([]dms.AuthorizedCAs, error)
}
