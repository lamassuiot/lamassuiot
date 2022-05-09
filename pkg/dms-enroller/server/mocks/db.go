package mocks

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/lamassuiot/lamassuiot/pkg/dms-enroller/common/dto"
	"github.com/lamassuiot/lamassuiot/pkg/dms-enroller/server/models/dms"
)

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

	id := "0"
	if ctx.Value("DBInsert") != nil {
		failDBLog := ctx.Value("DBInsert").(bool)

		if failDBLog {
			return id, errors.New("Error Insert")
		} else {
			return id, nil
		}
	}
	return id, nil
}
func (db *MockDB) SelectAllAuthorizedCAs(ctx context.Context) ([]dms.AuthorizedCAs, error) {
	return nil, nil
}

func (db *MockDB) SelectBySerialNumber(ctx context.Context, SerialNumber string) (string, error) {
	return "", nil
}
func (db *MockDB) SelectAll(ctx context.Context) ([]dto.DMS, error) {
	dmsArray := []dto.DMS{}
	dmsArray = append(dmsArray, testDMS(dms.ApprovedStatus))
	if ctx.Value("DBSelectAll") != nil {
		failDBLog := ctx.Value("DBSelectAll").(bool)

		if failDBLog {
			return []dto.DMS{}, errors.New("Error Select All")
		} else {
			return dmsArray, nil
		}
	}
	return []dto.DMS{}, nil
}

func (db *MockDB) SelectByID(ctx context.Context, id string) (dto.DMS, error) {
	var d dto.DMS
	switch id {
	case "1":
		d = testDMS(dms.ApprovedStatus)
	case "2":
		d = testDMS(dms.PendingStatus)
	case "3":
		d = testDMS(dms.RevokedStatus)
	case "4":
		d = testDMS(dms.DeniedStatus)
	}

	if ctx.Value("DBCsrBase64") != nil {
		failDBLog := ctx.Value("DBCsrBase64").(bool)
		if failDBLog {
			d.CsrBase64 = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ2pqQ0NBWFlDQVFBd1NURUxNQWtHQTFVRUJoTUNSVk14Q2pBSUJnTlZCQWdNQVVFeENqQUlCZ05WQkFjTQpBVUV4Q2pBSUJnTlZCQW9NQVVFeENqQUlCZ05WQkFzTUFVRXhDakFJQmdOVkJBTU1BVUV3Z2dFaU1BMEdDU3FHClNJYjNEUUVCQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUURDaFUxRFROckI0a2JTaVpjQjBMaHhUQ2dPYXlQUUU0VzkKT2N1MFBpczBybUliZnM2T2pERk5qcUY5dlhOcFlUSGhtL3FaTVZTWEZYZjM4VDBJS3NmU2lCYm5aa0pYWWc0NgptY2tLY1VkQ0VsUy8wK3RYaDh6Slo3QXNsV0Z2eXFLek5nUVJCcnhJQ0RVOTdVWXJ6eWk3ajVOSUJ2OHJvRld4CjVJOUNXUEpEQ00vRUFHMHVldjZQNVQzN2dKUzlFcnZXeERmWDVJL3hxRnZEQnpsV0VqbytFZ1piM3daSEt5d3QKMUVaVHBET1NKY29VeXZnWmFwUFF6U2JDZVdUL3ZlRW8rem5pUlk5SThFRlJhNm9DWDNCbVc4Snh2V2FSOVd3YQpnVUZ4cFM5OHdJN0JwSVJUeFgwdk9oMXZlUlBjWmRsVmFMZlJQb1BuV1BkdHAwckFDdXB6QWdNQkFBR2dBREFOCkJna3Foa2lHOXcwQkFRc0ZBQU9DQVFFQUllbTV5YnpVR1VvSk9yUjc1bW5COGZNUmVBWi9NalRVamYwem0xQjQKeGo4U1FMYTI2djU2ZkxOYkZ6NTlaaDlJa0J2U1AyNWNRTm5JU1lZT3RxejZLakJzcEVVQnNKaFVKcTNRNXpybgo3WVVoZnN2NWIzN0h2Y3h6akpvWW05NlZiU2FwQk5RWStGbjJ3R3NhZ1Zucktoalk0REdMM0lKQmlicmJvcEg2ClJwaFJRMWwyeXcwbUEybG9jK0hEZ1VwVTR4bXRpangvbHZmdHkzYVdwelBmV3pOWFRVYkEwNTFGY3hEQWh0SlkKbEd5WUxKSk1XQ08rL3NlUkxLSWFrZTFNeFR5Nzd0WVJ3MUNkVkJWWWFIbU8xM2k3ek8zYWVxdzloaGNHcWhyUQpXSWlYQ2lRdm9GN25oSmRvOEdmbkV5L1hKWk54LzQzbFVxUFcrekNhaWlsa2h3PT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUgUkVRVUVTVC0tLS0t"
		}
	}

	if ctx.Value("DBSelectByID") != nil {
		failDBLog := ctx.Value("DBSelectByID").(bool)

		if failDBLog {
			return dto.DMS{}, errors.New("Error Select By ID")
		} else {
			return d, nil
		}
	}
	return dto.DMS{}, nil
}

func (db *MockDB) UpdateByID(ctx context.Context, id string, status string, serialNumber string, encodedCsr string) (dto.DMS, error) {

	if ctx.Value("DBUpdateByID") != nil {
		failDBLog := ctx.Value("DBUpdateByID").(bool)

		if failDBLog {
			return dto.DMS{}, errors.New("Error Update By ID")
		} else {
			return dto.DMS{}, nil
		}
	}
	return dto.DMS{}, nil

}

func (db *MockDB) Delete(ctx context.Context, id string) error {
	if ctx.Value("DBDelete") != nil {
		failDBLog := ctx.Value("DBDelete").(bool)

		if failDBLog {
			return errors.New("Error Delete")
		} else {
			return nil
		}
	}
	return nil
}

func (db *MockDB) InsertAuthorizedCAs(ctx context.Context, dmsid string, CAs []string) error {
	return nil
}

func (db *MockDB) DeleteAuthorizedCAs(ctx context.Context, dmsid string) error {
	return nil
}

func (db *MockDB) SelectByDMSIDAuthorizedCAs(ctx context.Context, dmsid string) ([]dms.AuthorizedCAs, error) {
	return nil, nil
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
