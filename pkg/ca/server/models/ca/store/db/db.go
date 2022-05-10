package db

import (
	"context"
	"database/sql"
	"strconv"
	"strings"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/lamassuiot/lamassuiot/pkg/ca/common/dto"
	caerrors "github.com/lamassuiot/lamassuiot/pkg/ca/server/api/errors"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/models/ca"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/models/ca/store"
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
func (db *DB) SelectCertsbyCA(ctx context.Context, caName string, queryParameters dto.QueryParameters) ([]ca.IssuedCerts, int, error) {
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
	sqlStatement = applyFilter(sqlStatement, queryParameters)
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

func applyFilter(sqlStatement string, queryParameters dto.QueryParameters) string {

	if queryParameters.Order.Order != "" {
		if strings.ToUpper(queryParameters.Order.Order) == "ASC" || strings.ToUpper(queryParameters.Order.Order) == "DESC" {
			sqlStatement = sqlStatement + "ORDER BY " + queryParameters.Order.Field + " " + strings.ToUpper(queryParameters.Order.Order)
		}
	}
	if queryParameters.Pagination.Page != 0 {
		perPage := 100
		if queryParameters.Pagination.Offset > 0 {
			perPage = queryParameters.Pagination.Offset
		}
		sqlStatement = sqlStatement + " OFFSET " + strconv.Itoa(((queryParameters.Pagination.Page - 1) * perPage)) + " ROWS FETCH NEXT " + strconv.Itoa(perPage) + " ROWS ONLY"
	} else {

	}
	return sqlStatement
}
