package db

import (
	"context"
	"database/sql"
	"errors"

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
func (db *DB) InsertCa(ctx context.Context, caName string, caType string) error {
	sqlStatement := `
	INSERT INTO cas(ca_name, ca_type)
	VALUES($1, $2)
	RETURNING ca_name;
	`
	err := db.QueryRow(sqlStatement, caName, caType).Scan(&caName)
	if err != nil {
		level.Debug(db.logger).Log("err", err, "msg", "Could not insert "+caName+" in database")
		duplicationErr := &caerrors.DuplicateResourceError{
			ResourceType: "Insert CA DATABASE",
			ResourceId:   caName,
		}
		return duplicationErr
	}
	return nil

}
func (db *DB) SelectCas(ctx context.Context, caType string, queryParameters filters.QueryParameters) ([]ca.Cas, int, error) {
	var length int
	sqlStatement := `SELECT COUNT(*) as count FROM cas where ca_type = $1  `
	rows, err := db.Query(sqlStatement, caType)
	if err != nil {
		return []ca.Cas{}, 0, err
	}
	rows.Next()
	err = rows.Scan(&length)
	if err != nil {
		return []ca.Cas{}, 0, err
	}
	rows.Close()
	sqlStatement = `
	SELECT * FROM cas where ca_type = $1
	`
	sqlStatement = filters.ApplySQLFilter(sqlStatement, queryParameters)
	rows, err = db.Query(sqlStatement, caType)
	if err != nil {
		level.Debug(db.logger).Log("err", err, "msg", "Could not obtain CAs from database")
		notFoundErr := &caerrors.ResourceNotFoundError{
			ResourceType: "Select CAs DATABASE",
			ResourceId:   caType,
		}
		return []ca.Cas{}, 0, notFoundErr
	}
	defer rows.Close()

	var cas []ca.Cas
	for rows.Next() {
		var caName ca.Cas
		err := rows.Scan(&caName.CaName, &caName.CaType)
		if err != nil {
			return []ca.Cas{}, 0, err
		}
		cas = append(cas, caName)
	}
	return cas, length, nil
}
func (db *DB) DeleteCa(ctx context.Context, caName string) error {
	sqlStatement := `
	DELETE FROM cas
	WHERE ca_name = $1;
	`
	res, err := db.Exec(sqlStatement, caName)

	if err != nil {
		level.Debug(db.logger).Log("err", err, "msg", "Could not delete Device with ID "+caName+" from database")
		notFoundErr := &caerrors.ResourceNotFoundError{
			ResourceType: "Delete CA DATABASE",
			ResourceId:   caName,
		}
		return notFoundErr
	}
	count, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if count <= 0 {
		err = errors.New("no rows have been updated in database")
		level.Debug(db.logger).Log("err", err)
		return err
	}
	return nil
}
func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
}
