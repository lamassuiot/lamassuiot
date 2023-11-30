package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/go-gormigrate/gormigrate/v2"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/lamassuiot/lamassuiot/pkg/v3/storage"
	"github.com/lamassuiot/lamassuiot/pkg/v3/storage/postgres/migrations"
	"gorm.io/gorm"
)

const caDBName = "ca_certificates"
const caSchemaVersion = "2.4"

type PostgresCAStore struct {
	db      *gorm.DB
	querier *postgresDBQuerier[models.CACertificate]
}

func GetCAMigrationList() *DBMigrationList {
	mList := DBMigrationList{}
	mList.Insert("2.4", migrations.CertificateAuthorityFrom2_1To2_4Schema())

	return &mList
}

func NewCAPostgresRepository(db *gorm.DB) (storage.CACertificatesRepo, error) {
	vMetaTableName := "version_metadata"
	vQuerier, err := CheckAndCreateTable(db, vMetaTableName, "schema_version", DBVersion{})
	if err != nil {
		return nil, err
	}

	var lastAppliedSchemaV DBVersion
	tx := vQuerier.Table(vMetaTableName).Order("creation_ts DESC").Find(&lastAppliedSchemaV)
	if err := tx.Error; err != nil {
		if err != gorm.ErrRecordNotFound {
			db.Logger.Error(context.Background(), fmt.Sprintf("could not get version_metadata: %s", err))
			return nil, err
		}
	}

	insertCurrentDBVersion := func() error {
		vInsertTX := vQuerier.DB.Table(vMetaTableName).Create(DBVersion{CreationTS: time.Now(), SchemaVersion: caSchemaVersion})
		if err := vInsertTX.Error; err != nil {
			db.Logger.Error(context.Background(), fmt.Sprintf("could not insert version_metadata row: %s", err))
			return err
		}

		return nil
	}

	if tx.RowsAffected == 0 {
		db.Logger.Warn(context.Background(), "=====================================%v")
		db.Logger.Warn(context.Background(), fmt.Sprintf("no version_metadata record found. Setting schema to date version %s%v", caSchemaVersion))
		db.Logger.Warn(context.Background(), "this may result in DATA CORRUPTION as the AutoMigrator will adjust the datamodels to the latest version%v")
		db.Logger.Warn(context.Background(), "=====================================%v")

		if err := insertCurrentDBVersion(); err != nil {
			return nil, err
		}
	} else {
		if lastAppliedSchemaV.SchemaVersion != caSchemaVersion {
			//apply migration
			mList := GetCAMigrationList()
			nextMigration := mList.head
			for {
				if nextMigration.id == lastAppliedSchemaV.SchemaVersion {
					migrations := []*gormigrate.Migration{}
					db.Logger.Info(context.Background(), fmt.Sprintf("migration plan set to: %s", nextMigration.Show()))

					for {
						nextMigration := nextMigration.next
						if nextMigration == nil {
							break
						}

						migrations = append(migrations, nextMigration.migrations...)
					}

					m := gormigrate.New(db, gormigrate.DefaultOptions, migrations)
					if err = m.Migrate(); err != nil {
						db.Logger.Error(context.Background(), fmt.Sprintf("Migration failed: %v", err))
						return nil, err
					}

					db.Logger.Info(context.Background(), "DB successfully migrated to latest schema")
					if err := insertCurrentDBVersion(); err != nil {
						return nil, err
					}
				}
			}
		} else {
			db.Logger.Info(context.Background(), fmt.Sprintf("current DB schema up to date: %s", lastAppliedSchemaV.SchemaVersion))
		}
	}

	querier, err := CheckAndCreateTable(db, caDBName, "id", models.CACertificate{})
	if err != nil {
		return nil, err
	}

	return &PostgresCAStore{
		db:      db,
		querier: querier,
	}, nil
}

func (db *PostgresCAStore) Count(ctx context.Context) (int, error) {
	return db.querier.Count([]gormWhereParams{})
}

func (db *PostgresCAStore) CountByEngine(ctx context.Context, engineID string) (int, error) {
	return db.querier.Count([]gormWhereParams{
		{query: "engine_id = ?", extraArgs: []any{engineID}},
	})
}

func (db *PostgresCAStore) CountByStatus(ctx context.Context, status models.CertificateStatus) (int, error) {
	return db.querier.Count([]gormWhereParams{
		{query: "status = ?", extraArgs: []any{status}},
	})
}

func (db *PostgresCAStore) SelectByType(ctx context.Context, CAType models.CertificateType, req storage.StorageListRequest[models.CACertificate]) (string, error) {
	opts := []gormWhereParams{
		{query: "ca_meta_type = ?", extraArgs: []any{CAType}},
	}
	return db.querier.SelectAll(req.QueryParams, opts, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *PostgresCAStore) SelectAll(ctx context.Context, req storage.StorageListRequest[models.CACertificate]) (string, error) {
	return db.querier.SelectAll(req.QueryParams, []gormWhereParams{}, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *PostgresCAStore) SelectByCommonName(ctx context.Context, commonName string, req storage.StorageListRequest[models.CACertificate]) (string, error) {
	return db.querier.SelectAll(req.QueryParams, []gormWhereParams{
		{query: "subject_common_name = ? ", extraArgs: []any{commonName}},
	}, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *PostgresCAStore) SelectExistsBySerialNumber(ctx context.Context, serialNumber string) (bool, *models.CACertificate, error) {
	queryCol := "serial_number"
	return db.querier.SelectExists(serialNumber, &queryCol)
}

func (db *PostgresCAStore) SelectByParentCA(ctx context.Context, parentCAID string, req storage.StorageListRequest[models.CACertificate]) (string, error) {
	return db.querier.SelectAll(req.QueryParams, []gormWhereParams{
		{query: "issuer_meta_id = ? ", extraArgs: []any{parentCAID}},
	}, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *PostgresCAStore) SelectExistsByID(ctx context.Context, id string) (bool, *models.CACertificate, error) {
	return db.querier.SelectExists(id, nil)
}

func (db *PostgresCAStore) Insert(ctx context.Context, caCertificate *models.CACertificate) (*models.CACertificate, error) {
	return db.querier.Insert(*caCertificate, caCertificate.ID)
}

func (db *PostgresCAStore) Update(ctx context.Context, caCertificate *models.CACertificate) (*models.CACertificate, error) {
	return db.querier.Update(*caCertificate, caCertificate.ID)
}

func (db *PostgresCAStore) Delete(ctx context.Context, id string) error {
	return db.querier.Delete(id)
}
