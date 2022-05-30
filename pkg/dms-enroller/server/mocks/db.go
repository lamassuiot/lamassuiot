package mocks

import (
	"context"
	"database/sql"
	"os"
	"testing"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/lamassuiot/lamassuiot/pkg/dms-enroller/common/dto"
	dmserrors "github.com/lamassuiot/lamassuiot/pkg/dms-enroller/server/api/errors"
	"github.com/lamassuiot/lamassuiot/pkg/dms-enroller/server/models/dms"
)

var dmsDB dto.DMS
var authCAs []dms.AuthorizedCAs

type MockDB struct {
	*sql.DB
	logger log.Logger
}

func NewDB(t *testing.T) (*MockDB, error) {
	t.Helper()
	db, err := sql.Open("driverName", "dataSourceName")

	if err != nil {
		return nil, err
	}
	var logger log.Logger
	{
		logger = log.NewJSONLogger(os.Stdout)
		logger = log.With(logger, "ts", log.DefaultTimestampUTC)
		logger = level.NewFilter(logger, level.AllowInfo())
		logger = log.With(logger, "caller", log.DefaultCaller)
	}

	return &MockDB{db, logger}, nil

}

func checkDBAlive(db *MockDB) error {
	sqlStatement := `
	SELECT WHERE 1=0`
	_, err := db.Query(sqlStatement)
	return err
}

func (db *MockDB) Insert(ctx context.Context, d dto.DMS) (string, error) {
	if d.Id == dmsDB.Id {
		duplicationErr := &dmserrors.DuplicateResourceError{
			ResourceType: "Insert DMS",
			ResourceId:   d.Id,
		}
		return "", duplicationErr
	} else {
		dmsDB = d
		return dmsDB.Id, nil
	}

}
func (db *MockDB) SelectAllAuthorizedCAs(ctx context.Context) ([]dms.AuthorizedCAs, error) {
	if len(authCAs) == 0 {
		notFoundErr := &dmserrors.ResourceNotFoundError{
			ResourceType: "DMS",
			ResourceId:   "Database is empty",
		}
		return []dms.AuthorizedCAs{}, notFoundErr
	} else {
		return authCAs, nil
	}
}

func (db *MockDB) SelectBySerialNumber(ctx context.Context, SerialNumber string) (string, error) {
	if SerialNumber != dmsDB.SerialNumber {
		notFoundErr := &dmserrors.ResourceNotFoundError{
			ResourceType: "DMS",
			ResourceId:   SerialNumber,
		}
		return "", notFoundErr
	} else {
		return dmsDB.Id, nil
	}
}
func (db *MockDB) SelectAll(ctx context.Context) ([]dto.DMS, error) {
	dmsArray := []dto.DMS{}
	if dmsDB.Id == "" {
		notFoundErr := &dmserrors.ResourceNotFoundError{
			ResourceType: "Select All DMS",
			ResourceId:   "Database is empty",
		}
		return []dto.DMS{}, notFoundErr
	} else {
		dmsArray = append(dmsArray, dmsDB)
		return dmsArray, nil
	}

}

func (db *MockDB) SelectByID(ctx context.Context, id string) (dto.DMS, error) {
	if id != dmsDB.Id {
		notFoundErr := &dmserrors.ResourceNotFoundError{
			ResourceType: "Select DMS by ID",
			ResourceId:   id,
		}
		return dto.DMS{}, notFoundErr
	} else {
		return dmsDB, nil
	}
}

func (db *MockDB) UpdateByID(ctx context.Context, id string, status string, serialNumber string, encodedCsr string) (dto.DMS, error) {

	if id != dmsDB.Id {
		notFoundErr := &dmserrors.ResourceNotFoundError{
			ResourceType: "Update DMS",
			ResourceId:   id,
		}
		return dto.DMS{}, notFoundErr
	} else {
		dmsDB.Status = status
		dmsDB.SerialNumber = serialNumber
		dmsDB.CsrBase64 = encodedCsr
		return dmsDB, nil
	}

}

func (db *MockDB) Delete(ctx context.Context, id string) error {
	if id != dmsDB.Id {
		notFoundErr := &dmserrors.ResourceNotFoundError{
			ResourceType: "Delete DMS",
			ResourceId:   id,
		}
		return notFoundErr
	} else {
		return nil
	}
}

func (db *MockDB) InsertAuthorizedCAs(ctx context.Context, dmsid string, CAs []string) error {
	if len(CAs) != 1 {
		for i := 0; i < len(CAs); i++ {
			if CAs[i] == CAs[i+1] {
				duplicationErr := &dmserrors.DuplicateResourceError{
					ResourceType: "Insert AuthCAs DMS",
					ResourceId:   dmsid,
				}
				return duplicationErr
			}
		}
	}
	if len(authCAs) == 0 {
		for i := 0; i < len(CAs); i++ {
			cas := dms.AuthorizedCAs{
				DmsId:  dmsid,
				CaName: CAs[i],
			}
			authCAs = append(authCAs, cas)
		}
	} else {
		var lenAuthCas = len(authCAs)
		for i := 0; i < len(CAs); i++ {
			for j := 0; j < lenAuthCas; j++ {
				if authCAs[j].DmsId == dmsid && authCAs[j].CaName == CAs[i] {
					duplicationErr := &dmserrors.DuplicateResourceError{
						ResourceType: "Insert AuthCAs DMS",
						ResourceId:   dmsid,
					}
					return duplicationErr
				} else {
					cas := dms.AuthorizedCAs{
						DmsId:  dmsid,
						CaName: CAs[i],
					}
					authCAs = append(authCAs, cas)
				}
			}
		}
	}

	return nil
}

func (db *MockDB) DeleteAuthorizedCAs(ctx context.Context, dmsid string) error {
	var count = 0
	for i := 0; i < len(authCAs); i++ {
		if authCAs[i].DmsId != dmsid {
			count++
		}
	}
	if count == len(authCAs) {
		notFoundErr := &dmserrors.ResourceNotFoundError{
			ResourceType: "DMS",
			ResourceId:   dmsid,
		}
		return notFoundErr
	} else {
		return nil
	}

}

func (db *MockDB) SelectByDMSIDAuthorizedCAs(ctx context.Context, dmsid string) ([]dms.AuthorizedCAs, error) {
	var count = 0
	var cas []dms.AuthorizedCAs
	for i := 0; i < len(authCAs); i++ {
		if authCAs[i].DmsId != dmsid {
			count++
		} else {
			casauth := dms.AuthorizedCAs{
				DmsId:  dmsid,
				CaName: authCAs[i].CaName,
			}
			cas = append(cas, casauth)
		}
	}
	if count == len(authCAs) {
		notFoundErr := &dmserrors.ResourceNotFoundError{
			ResourceType: "	Select DMS Auth CAs",
			ResourceId: dmsid,
		}
		return []dms.AuthorizedCAs{}, notFoundErr
	} else {
		return cas, nil
	}
}

func testDMS(status string) dto.DMS {

	key := dto.PrivateKeyMetadataWithStregth{
		KeyType:     "RSA",
		KeyBits:     3072,
		KeyStrength: "low",
	}
	device := dto.DMS{
		Id:               "1",
		Name:             "test",
		SerialNumber:     "23-33-5b-19-c8-ed-8b-2a-92-5c-7b-57-fc-47-45-e7-12-03-91-23",
		KeyMetadata:      key,
		Status:           status,
		CsrBase64:        "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNURENDQWZPZ0F3SUJBZ0lVZnRXcTVObnpXZHUrSHk2S1RTMmpWazcybzRjd0NnWUlLb1pJemowRUF3SXcKY3pFTE1Ba0dBMVVFQmhNQ1JWTXhFVEFQQmdOVkJBZ1RDRWRwY0hWNmEyOWhNUkV3RHdZRFZRUUhFd2hCY25KaApjMkYwWlRFaE1BNEdBMVVFQ2hNSFV5NGdRMjl2Y0RBUEJnTlZCQW9UQ0V4TFV5Qk9aWGgwTVJzd0dRWURWUVFECkV4Sk1TMU1nVG1WNGRDQlNiMjkwSUVOQklETXdJQmNOTWpJd01USXdNVEV3TWpJMVdoZ1BNakExTWpBeE1UTXgKTVRBeU5UVmFNSE14Q3pBSkJnTlZCQVlUQWtWVE1SRXdEd1lEVlFRSUV3aEhhWEIxZW10dllURVJNQThHQTFVRQpCeE1JUVhKeVlYTmhkR1V4SVRBT0JnTlZCQW9UQjFNdUlFTnZiM0F3RHdZRFZRUUtFd2hNUzFNZ1RtVjRkREViCk1Ca0dBMVVFQXhNU1RFdFRJRTVsZUhRZ1VtOXZkQ0JEUVNBek1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMEQKQVFjRFFnQUU1aTFxZnlZU2xLaWt3SDhGZkhvQWxVWE44RlE3aE1OMERaTk8vVzdiSE44NVFpZ09ZeVQ1bWNYMgpXbDJtSTVEL0xQT1BKd0l4N1ZZcmxZU1BMTm5ndjZOak1HRXdEZ1lEVlIwUEFRSC9CQVFEQWdFR01BOEdBMVVkCkV3RUIvd1FGTUFNQkFmOHdIUVlEVlIwT0JCWUVGUGRURSs3a0k2MXFXSHFtUktZai9OaElIS01lTUI4R0ExVWQKSXdRWU1CYUFGUGRURSs3a0k2MXFXSHFtUktZai9OaElIS01lTUFvR0NDcUdTTTQ5QkFNQ0EwY0FNRVFDSUI2QQptZStjRzQ0MjBpNE5QZ1ZwWVRHN3hFN2lvbG0xOXhqRC9PcS9TeWt0QWlBaWRBK2JTanpvVHZxckRieDBqaHBiCmJpTnFycHZJY255TEY1MXQ5cHdBL1E9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0t",
		CerificateBase64: "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFNWkxcWZ5WVNsS2lrd0g4RmZIb0FsVVhOOEZRNwpoTU4wRFpOTy9XN2JITjg1UWlnT1l5VDVtY1gyV2wybUk1RC9MUE9QSndJeDdWWXJsWVNQTE5uZ3Z3PT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg",
	}

	return device
}
