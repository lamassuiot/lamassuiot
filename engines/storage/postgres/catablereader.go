package postgres

import (
	"context"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// CATableReader lists CAs from the ca_certificates and certificates tables alone. Unlike the CA repository
// it does not read certificates_view, so it also works on a ca schema of an earlier version: the
// ca-to-kms-migration tool has to run before the ca migrations, which need the keys it registers.
// The certificates it returns leave HasPrivateKey unset.
type CATableReader struct {
	querier *DBQuerier[models.CACertificate]
}

func NewCATableReader(log *logrus.Entry, db *gorm.DB) (*CATableReader, error) {
	querier, err := TableQuery(log, db, caDBName, "id", models.CACertificate{})
	if err != nil {
		return nil, err
	}
	return &CATableReader{querier: querier}, nil
}

func (r *CATableReader) SelectByType(ctx context.Context, CAType models.CertificateType, req storage.StorageListRequest[models.CACertificate]) (string, error) {
	opts := []GormExtraOps{
		{Query: "certificates.type = ? ", AdditionalWhere: []any{CAType}, Joins: []string{"JOIN certificates ON ca_certificates.serial_number = certificates.serial_number"}},
	}
	return r.querier.SelectAll(ctx, req.QueryParams, opts, req.ExhaustiveRun, req.ApplyFunc)
}
