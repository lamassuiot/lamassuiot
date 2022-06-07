package store

import (
	"context"

	"github.com/lamassuiot/lamassuiot/pkg/dms-enroller/common/dto"
	"github.com/lamassuiot/lamassuiot/pkg/dms-enroller/server/models/dms"
	"github.com/lamassuiot/lamassuiot/pkg/utils/server/filters"
)

type DB interface {
	Insert(ctx context.Context, d dto.DMS) (string, error)
	SelectAll(ctx context.Context, queryParameters filters.QueryParameters) ([]dto.DMS, int, error)
	SelectByID(ctx context.Context, id string) (dto.DMS, error)
	SelectBySerialNumber(ctx context.Context, SerialNumber string) (string, error)
	UpdateByID(ctx context.Context, id string, status string, serialNumber string, encodedCsr string) (dto.DMS, error)
	Delete(ctx context.Context, id string) error
	InsertAuthorizedCAs(ctx context.Context, dmsid string, CAs []string) error
	DeleteAuthorizedCAs(ctx context.Context, dmsid string) error
	SelectByDMSIDAuthorizedCAs(ctx context.Context, dmsid string) ([]dms.AuthorizedCAs, error)
	SelectAllAuthorizedCAs(ctx context.Context) ([]dms.AuthorizedCAs, error)
	//CountEnrolledDevices(ctx context.Context, dms_id string) (int, error)
}
