package db

import (
	"context"
	"database/sql"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	caerrors "github.com/lamassuiot/lamassuiot/pkg/ca/server/api/errors"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/models/ca"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/models/ca/store"
	"github.com/lamassuiot/lamassuiot/pkg/utils/server/filters"
)

func NewDB(db *sql.DB, logger log.Logger) store.DB {
	return &DB{db, logger}
}

type DB struct {
	*sql.DB
	logger log.Logger
}

func checkDBAlive(db *sql.DB) error {
	sqlStatement := `
	SELECT WHERE 1=0`
	_, err := db.Query(sqlStatement)
	return err
}
func (db *DB) InsertCert(ctx context.Context, caName string, serialNumber string) error {
	sqlStatement := `
	INSERT INTO ca_issued_certs(ca_name, serial_number)
	VALUES($1, $2)
	RETURNING serial_number;
	`
	err := db.QueryRow(sqlStatement, caName, serialNumber).Scan(&serialNumber)
	if err != nil {
		level.Debug(db.logger).Log("err", err, "msg", "Could not insert Serial Number "+serialNumber+" in database")
		duplicationErr := &caerrors.DuplicateResourceError{
			ResourceType: "CA DATABASE",
			ResourceId:   serialNumber,
		}
		return duplicationErr
	}
	return nil

}
func (db *DB) SelectCertsByCA(ctx context.Context, caName string, queryParameters filters.QueryParameters) ([]ca.IssuedCerts, int, error) {
	var length int
	sqlStatement := `SELECT COUNT(*) as count FROM ca_issued_certs where ca_name = $1  `
	rows, err := db.Query(sqlStatement, caName)
	if err != nil {
		return []ca.IssuedCerts{}, 0, err
	}
	rows.Next()
	err = rows.Scan(&length)
	if err != nil {
		return []ca.IssuedCerts{}, 0, err
	}
	rows.Close()
	sqlStatement = `
	SELECT * FROM ca_issued_certs where ca_name = $1
	`
	sqlStatement = filters.ApplySQLFilter(sqlStatement, queryParameters)
	rows, err = db.Query(sqlStatement, caName)
	if err != nil {
		level.Debug(db.logger).Log("err", err, "msg", "Could not obtain Certs Serial Numbers from database")
		notFoundErr := &caerrors.ResourceNotFoundError{
			ResourceType: "CA DATABASE",
			ResourceId:   caName,
		}
		return []ca.IssuedCerts{}, 0, notFoundErr
	}
	defer rows.Close()

	var certs []ca.IssuedCerts
	for rows.Next() {
		var cert ca.IssuedCerts
		err := rows.Scan(&cert.CaName, &cert.SerialNumber)
		if err != nil {
			return []ca.IssuedCerts{}, 0, err
		}
		certs = append(certs, cert)
	}
	return certs, length, nil
}

func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
}
