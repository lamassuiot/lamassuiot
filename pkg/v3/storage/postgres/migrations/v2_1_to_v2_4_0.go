package migrations

import (
	"time"

	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

func CertificateAuthorityFrom2_1To2_4Schema() []*gormigrate.Migration {
	t := time.Date(2023, time.November, 28, 7, 0, 0, 0, time.UTC)
	m := []*gormigrate.Migration{{
		ID: t.Format("200601021504"),
		Migrate: func(d *gorm.DB) error {
			return nil
		},
	}}

	return m
}
