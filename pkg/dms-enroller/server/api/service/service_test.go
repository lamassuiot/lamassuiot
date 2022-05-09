package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"
	"testing"

	"github.com/go-kit/log"
	"github.com/lamassuiot/lamassuiot/pkg/dms-enroller/common/dto"
	"github.com/lamassuiot/lamassuiot/pkg/dms-enroller/server/mocks"
	"github.com/lamassuiot/lamassuiot/pkg/dms-enroller/server/models/dms"
	"github.com/lamassuiot/lamassuiot/pkg/utils"
)

func TestUpdateDMSStatus(t *testing.T) {
	srv, ctx := setup(t)

	testCases := []struct {
		name      string
		DMSstatus string
		id        string
		ret       error
	}{
		{"Status aproved prevDMS pending error update", dms.ApprovedStatus, "2", errors.New("Error Update By ID")},
		{"Status Revoked prevDMS not approved", dms.RevokedStatus, "2", nil},
		{"Status Revoked prevDMS not approved", dms.ApprovedStatus, "2", nil},
		{"Status Default", "", "2", nil},
		{"Error getting certificate Revoked", dms.RevokedStatus, "1", errors.New("Error revoking certificate")},
		{"Error approving cert", dms.ApprovedStatus, "2", errors.New("Error revoking certificate")},
		{"Error Parse Certificate Request", dms.ApprovedStatus, "2", errors.New("asn1: structure error: tags don't match (2 vs {class:2 tag:0 length:3 isCompound:true}) {optional:false explicit:false application:false private:false defaultValue:<nil> tag:<nil> stringType:0 timeType:0 set:false omitEmpty:false} int @2")},

		{"Error revoking cert", dms.RevokedStatus, "1", errors.New("Error revoking certificate")},
		{"Correct Approved", dms.ApprovedStatus, "1", nil},
		{"Correct Revoked", dms.RevokedStatus, "1", nil},
		{"Correct Denied", dms.DeniedStatus, "1", nil},
		{"Error finding ID", "", "1", errors.New("Error Select By ID")},
		{"Error getting certificate Approved", dms.ApprovedStatus, "1", errors.New("Error Update By ID")},

		{"Error getting certificate Denied", dms.DeniedStatus, "4", errors.New("Error Update By ID")},
		{"Error revoked update", dms.RevokedStatus, "1", errors.New("Error Update By ID")},
		{"Error denied update", dms.DeniedStatus, "2", errors.New("Error Update By ID")},
	}
	for _, tc := range testCases {

		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {

			if tc.name == "Status aproved prevDMS pending error update" {
				ctx = context.WithValue(ctx, "DBSelectByID", false)
				ctx = context.WithValue(ctx, "DBUpdateByID", true)
				ctx = context.WithValue(ctx, "RevokeCertShouldFail", false)
				ctx = context.WithValue(ctx, "RevokeCertShouldFail", false)
				ctx = context.WithValue(ctx, "SignCertificateRequestFail", false)
				ctx = context.WithValue(ctx, "DBCsrBase64", true)
			} else if tc.name == "Error getting certificate Revoked" {
				ctx = context.WithValue(ctx, "DBSelectByID", false)
				ctx = context.WithValue(ctx, "DBUpdateByID", false)
				ctx = context.WithValue(ctx, "RevokeCertShouldFail", true)
			} else if tc.name == "Error finding ID" {
				ctx = context.WithValue(ctx, "DBSelectByID", true)
				ctx = context.WithValue(ctx, "DBUpdateByID", false)
			} else if tc.name == "Error getting certificate Approved" || tc.name == "Error getting certificate Revoked" || tc.name == "Error getting certificate Denied" || tc.name == "Error denied update" || tc.name == "Error revoked update" || tc.name == "tatus Revoked prevDMS not approved" {
				ctx = context.WithValue(ctx, "DBSelectByID", false)
				ctx = context.WithValue(ctx, "DBUpdateByID", true)
				ctx = context.WithValue(ctx, "SignCertificateRequestFail", false)
			} else if tc.name == "Error updating certificate Revoked" {
				ctx = context.WithValue(ctx, "DBSelectByID", false)
				ctx = context.WithValue(ctx, "DBUpdateByID", true)
				ctx = context.WithValue(ctx, "SignCertificateRequestFail", false)
			} else if tc.name == "Error revoking cert" {
				ctx = context.WithValue(ctx, "DBSelectByID", false)
				ctx = context.WithValue(ctx, "DBUpdateByID", false)
				ctx = context.WithValue(ctx, "RevokeCertShouldFail", true)
			} else if tc.name == "Error approving cert" {
				ctx = context.WithValue(ctx, "DBSelectByID", false)
				ctx = context.WithValue(ctx, "DBUpdateByID", false)
				ctx = context.WithValue(ctx, "RevokeCertShouldFail", false)
				ctx = context.WithValue(ctx, "SignCertificateRequestFail", true)
				ctx = context.WithValue(ctx, "DBCsrBase64", true)
			} else if tc.name == "Status Revoked prevDMS not approved" {
				ctx = context.WithValue(ctx, "DBSelectByID", false)
				ctx = context.WithValue(ctx, "DBUpdateByID", false)
				ctx = context.WithValue(ctx, "RevokeCertShouldFail", false)
				ctx = context.WithValue(ctx, "SignCertificateRequestFail", false)
				ctx = context.WithValue(ctx, "DBCsrBase64", true)
			} else {
				ctx = context.WithValue(ctx, "DBSelectByID", false)
				ctx = context.WithValue(ctx, "DBUpdateByID", false)
				ctx = context.WithValue(ctx, "RevokeCertShouldFail", false)
				ctx = context.WithValue(ctx, "SignCertificateRequestFail", false)
				ctx = context.WithValue(ctx, "DBCsrBase64", false)
			}
			//TODO: test with CA list
			_, err := srv.UpdateDMSStatus(ctx, tc.DMSstatus, tc.id, nil)
			if err != nil {
				if err.Error() != tc.ret.Error() {
					t.Errorf("Got result is %s; want %s", err, tc.ret)
				}
			}
		})
	}
}
func TestCreateDMS(t *testing.T) {
	srv, ctx := setup(t)

	csrRSA := "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ2pqQ0NBWFlDQVFBd1NURUxNQWtHQTFVRUJoTUNSVk14Q2pBSUJnTlZCQWdNQVVFeENqQUlCZ05WQkFjTQpBVUV4Q2pBSUJnTlZCQW9NQVVFeENqQUlCZ05WQkFzTUFVRXhDakFJQmdOVkJBTU1BVUV3Z2dFaU1BMEdDU3FHClNJYjNEUUVCQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUURDaFUxRFROckI0a2JTaVpjQjBMaHhUQ2dPYXlQUUU0VzkKT2N1MFBpczBybUliZnM2T2pERk5qcUY5dlhOcFlUSGhtL3FaTVZTWEZYZjM4VDBJS3NmU2lCYm5aa0pYWWc0NgptY2tLY1VkQ0VsUy8wK3RYaDh6Slo3QXNsV0Z2eXFLek5nUVJCcnhJQ0RVOTdVWXJ6eWk3ajVOSUJ2OHJvRld4CjVJOUNXUEpEQ00vRUFHMHVldjZQNVQzN2dKUzlFcnZXeERmWDVJL3hxRnZEQnpsV0VqbytFZ1piM3daSEt5d3QKMUVaVHBET1NKY29VeXZnWmFwUFF6U2JDZVdUL3ZlRW8rem5pUlk5SThFRlJhNm9DWDNCbVc4Snh2V2FSOVd3YQpnVUZ4cFM5OHdJN0JwSVJUeFgwdk9oMXZlUlBjWmRsVmFMZlJQb1BuV1BkdHAwckFDdXB6QWdNQkFBR2dBREFOCkJna3Foa2lHOXcwQkFRc0ZBQU9DQVFFQUllbTV5YnpVR1VvSk9yUjc1bW5COGZNUmVBWi9NalRVamYwem0xQjQKeGo4U1FMYTI2djU2ZkxOYkZ6NTlaaDlJa0J2U1AyNWNRTm5JU1lZT3RxejZLakJzcEVVQnNKaFVKcTNRNXpybgo3WVVoZnN2NWIzN0h2Y3h6akpvWW05NlZiU2FwQk5RWStGbjJ3R3NhZ1Zucktoalk0REdMM0lKQmlicmJvcEg2ClJwaFJRMWwyeXcwbUEybG9jK0hEZ1VwVTR4bXRpangvbHZmdHkzYVdwelBmV3pOWFRVYkEwNTFGY3hEQWh0SlkKbEd5WUxKSk1XQ08rL3NlUkxLSWFrZTFNeFR5Nzd0WVJ3MUNkVkJWWWFIbU8xM2k3ek8zYWVxdzloaGNHcWhyUQpXSWlYQ2lRdm9GN25oSmRvOEdmbkV5L1hKWk54LzQzbFVxUFcrekNhaWlsa2h3PT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUgUkVRVUVTVC0tLS0t"
	csrError := "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNURENDQWZPZ0F3SUJBZ0lVZnRXcTVObnpXZHUrSHk2S1RTMmpWazcybzRjd0NnWUlLb1pJemowRUF3SXcKY3pFTE1Ba0dBMVVFQmhNQ1JWTXhFVEFQQmdOVkJBZ1RDRWRwY0hWNmEyOWhNUkV3RHdZRFZRUUhFd2hCY25KaApjMkYwWlRFaE1BNEdBMVVFQ2hNSFV5NGdRMjl2Y0RBUEJnTlZCQW9UQ0V4TFV5Qk9aWGgwTVJzd0dRWURWUVFECkV4Sk1TMU1nVG1WNGRDQlNiMjkwSUVOQklETXdJQmNOTWpJd01USXdNVEV3TWpJMVdoZ1BNakExTWpBeE1UTXgKTVRBeU5UVmFNSE14Q3pBSkJnTlZCQVlUQWtWVE1SRXdEd1lEVlFRSUV3aEhhWEIxZW10dllURVJNQThHQTFVRQpCeE1JUVhKeVlYTmhkR1V4SVRBT0JnTlZCQW9UQjFNdUlFTnZiM0F3RHdZRFZRUUtFd2hNUzFNZ1RtVjRkREViCk1Ca0dBMVVFQXhNU1RFdFRJRTVsZUhRZ1VtOXZkQ0JEUVNBek1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMEQKQVFjRFFnQUU1aTFxZnlZU2xLaWt3SDhGZkhvQWxVWE44RlE3aE1OMERaTk8vVzdiSE44NVFpZ09ZeVQ1bWNYMgpXbDJtSTVEL0xQT1BKd0l4N1ZZcmxZU1BMTm5ndjZOak1HRXdEZ1lEVlIwUEFRSC9CQVFEQWdFR01BOEdBMVVkCkV3RUIvd1FGTUFNQkFmOHdIUVlEVlIwT0JCWUVGUGRURSs3a0k2MXFXSHFtUktZai9OaElIS01lTUI4R0ExVWQKSXdRWU1CYUFGUGRURSs3a0k2MXFXSHFtUktZai9OaElIS01lTUFvR0NDcUdTTTQ5QkFNQ0EwY0FNRVFDSUI2QQptZStjRzQ0MjBpNE5QZ1ZwWVRHN3hFN2lvbG0xOXhqRC9PcS9TeWt0QWlBaWRBK2JTanpvVHZxckRieDBqaHBiCmJpTnFycHZJY255TEY1MXQ5cHdBL1E9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0t"
	//csrECDSA := "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQml6Q0I3Z0lCQURCSk1Rc3dDUVlEVlFRR0V3SkZVekVLTUFnR0ExVUVDQXdCUVRFS01BZ0dBMVVFQnd3QgpRVEVLTUFnR0ExVUVDZ3dCUVRFS01BZ0dBMVVFQ3d3QlFURUtNQWdHQTFVRUF3d0JRVENCbXpBUUJnY3Foa2pPClBRSUJCZ1VyZ1FRQUl3T0JoZ0FFQWFSaC9nZFpMMGo2ZGZ5d2NLaU1HSkN3RTVvVk1BWVpZV3BHa2gyUWFuMFYKOWR3ZjhQUS9wZnlMVGpEeVFCVVVxckxOQlQ5ZEFPcFczZHYvZlV4UFVnZWJBQVhSUVBVMUVLV2NNb2pZWTkvaQptVXBQMnlsNHVHUUdBQXlUQzdmUG5NbzNZVkd5cU5uZ2ZQK0N5WE1INnoxUGtGZk1xcFZHM0Z0dGhnSmZvcWt2CnNabWFvQUF3Q2dZSUtvWkl6ajBFQXdJRGdZc0FNSUdIQWtFSm9lS3E2Y1greU9xVk5lQzIyZ1IzaGFaSjlqMm4KSkR6bkVvT3E4Y29qT1h5M2J1MTJDUlptWTU5UUFFK1JJRTJiWk56TGtqMWJQcE1jUlBad0s1R0l5UUpDQU5lMwoxUnAyTUVKS0NsNitnMHk4WlpHU0VwUmdoaCtueUpuNXJ3OTZzVEcyQVlpV0NVTWxvVSt1eGdieDBocDdKNkR3Cm55QVZrbnE3bkVGT2thNkZLdzhFCi0tLS0tRU5EIENFUlRJRklDQVRFIFJFUVVFU1QtLS0tLQ=="

	testCases := []struct {
		name    string
		csr     string
		dmsName string
		ret     error
	}{
		//{"Correct ECDSA", csrECDSA, "a", errors.New("Error")},
		{"Error DecodeB64", "\x00\x00\x00", "a", errors.New("illegal base64 data at input byte 0")},
		{"Correct RSA", csrRSA, "a", errors.New("Error")},

		{"Error Insert", csrRSA, "a", errors.New("Error Insert")},
		{"Error Parse Certificate Request", csrError, "a", errors.New("asn1: structure error: tags don't match (2 vs {class:2 tag:0 length:3 isCompound:true}) {optional:false explicit:false application:false private:false defaultValue:<nil> tag:<nil> stringType:0 timeType:0 set:false omitEmpty:false} int @2")},
	}
	for _, tc := range testCases {

		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {

			if tc.name == "Error Insert" {
				ctx = context.WithValue(ctx, "DBInsert", true)
			} else if tc.name == "Error Parse Certificate Request" {
				ctx = context.WithValue(ctx, "DBInsert", false)
			} else {
				ctx = context.WithValue(ctx, "DBInsert", false)
			}
			_, err := srv.CreateDMS(ctx, tc.csr, tc.dmsName)
			if err != nil {
				if err.Error() != tc.ret.Error() {
					t.Errorf("Got result is %s; want %s", err, tc.ret)
				}
			}
		})
	}
}
func TestGetDMSs(t *testing.T) {
	srv, ctx := setup(t)

	testCases := []struct {
		name string
		ret  error
	}{

		{"Correct", errors.New("Error Select All")},
		{"Incorrect", errors.New("Error Select All")},
	}
	for _, tc := range testCases {

		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {

			if tc.name == "Incorrect" {
				ctx = context.WithValue(ctx, "DBSelectAll", true)
			} else {
				ctx = context.WithValue(ctx, "DBSelectAll", false)
				ctx = context.WithValue(ctx, "GetCertFail", false)

			}
			_, err := srv.GetDMSs(ctx)
			if err != nil {
				if err.Error() != tc.ret.Error() {
					t.Errorf("Got result is %s; want %s", err, tc.ret)
				}
			}
		})
	}
}

func TestCreateDMSForm(t *testing.T) {
	srv, ctx := setup(t)

	subject := dto.Subject{
		C:  "C",
		CN: "CN",
		O:  "O",
		L:  "L",
		OU: "OU",
		ST: "ST",
	}

	RSAkey := dto.PrivateKeyMetadata{
		KeyType: "RSA",
		KeyBits: 4096,
	}
	ECkeyUnsupported := dto.PrivateKeyMetadata{
		KeyType: "EC",
		KeyBits: 4096,
	}
	ECkey224 := dto.PrivateKeyMetadata{
		KeyType: "EC",
		KeyBits: 224,
	}
	ECkey256 := dto.PrivateKeyMetadata{
		KeyType: "EC",
		KeyBits: 256,
	}
	ECkey384 := dto.PrivateKeyMetadata{
		KeyType: "EC",
		KeyBits: 384,
	}
	ECkey521 := dto.PrivateKeyMetadata{
		KeyType: "EC",
		KeyBits: 521,
	}
	Undeclaredkey := dto.PrivateKeyMetadata{
		KeyType: "fgd",
		KeyBits: 4096,
	}
	testCases := []struct {
		name    string
		subject dto.Subject
		key     dto.PrivateKeyMetadata
		url     string
		dmsName string
		ret     error
	}{
		{"RSA Key", subject, RSAkey, "a", "A", nil},
		{"EC Key Error", subject, ECkey224, "a", "A", errors.New("illegal base64 data at input byte 0")},
		{"EC Key Error", subject, ECkey256, "a", "A", errors.New("illegal base64 data at input byte 0")},
		{"EC Key Error", subject, ECkey384, "a", "A", errors.New("illegal base64 data at input byte 0")},
		{"EC Key Error", subject, ECkey521, "a", "A", errors.New("illegal base64 data at input byte 0")},
		{"EC Key Unsupported", subject, ECkeyUnsupported, "a", "A", errors.New("Unsupported key length")},
		{"Undeclared Key", subject, Undeclaredkey, "a", "A", errors.New("Invalid key format")},
		{"CreateDMS", subject, RSAkey, "a", "A", errors.New("Invalid key format")},
	}
	for _, tc := range testCases {

		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {

			if tc.name == "Error Insert" {
				ctx = context.WithValue(ctx, "DBInsert", true)
			} else if tc.name == "Error Parse Certificate Request" {
				ctx = context.WithValue(ctx, "DBInsert", false)
			} else {
				ctx = context.WithValue(ctx, "DBInsert", false)
			}
			_, _, err := srv.CreateDMSForm(ctx, tc.subject, tc.key, tc.dmsName)
			if err != nil {
				if err.Error() != tc.ret.Error() {
					t.Errorf("Got result is %s; want %s", err, tc.ret)
				}
			}
		})
	}
}

func TestDeleteDMS(t *testing.T) {
	srv, ctx := setup(t)

	testCases := []struct {
		name string
		id   string
		ret  error
	}{

		{"Correct", "1", nil},
		{"Error finding ID", "1", errors.New("Error Select By ID")},
		{"Error Delete", "3", errors.New("Error Delete")},
	}
	for _, tc := range testCases {

		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {

			if tc.name == "Error finding ID" {
				ctx = context.WithValue(ctx, "DBSelectByID", true)
				ctx = context.WithValue(ctx, "DBDelete", false)
			} else if tc.name == "Error Delete" {
				ctx = context.WithValue(ctx, "DBSelectByID", false)
				ctx = context.WithValue(ctx, "DBDelete", true)
			} else {
				ctx = context.WithValue(ctx, "DBSelectByID", false)
				ctx = context.WithValue(ctx, "DBDelete", false)
			}
			err := srv.DeleteDMS(ctx, tc.id)
			if err != nil {
				if err.Error() != tc.ret.Error() {
					t.Errorf("Got result is %s; want %s", err, tc.ret)
				}
			}
		})
	}
}

func TestHealth(t *testing.T) {
	srv, ctx := setup(t)
	type testCasesHealth struct {
		name string
		ret  bool
	}
	cases := []testCasesHealth{
		{"Correct", true},
	}
	for _, tc := range cases {

		out := srv.Health(ctx)
		if tc.ret != out {
			t.Errorf("Expected '%s', but got '%s'", strconv.FormatBool(tc.ret), strconv.FormatBool(out))
		}

	}
}

func setup(t *testing.T) (Service, context.Context) {
	t.Helper()

	buf := &bytes.Buffer{}
	logger := log.NewJSONLogger(buf)
	ctx := context.Background()
	ctx = context.WithValue(ctx, utils.LamassuLoggerContextKey, logger)

	dmsDb, _ := mocks.NewDB(t)

	lamassuCaClient, _ := mocks.NewLamassuCaClientMock(logger)

	srv := NewEnrollerService(dmsDb, &lamassuCaClient, logger)
	return srv, ctx
}
