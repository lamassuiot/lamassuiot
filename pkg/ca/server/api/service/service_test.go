package service

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"testing"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/lamassuiot/lamassuiot/pkg/ca/common/dto"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/mocks"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/secrets"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/secrets/vault"
	"github.com/lamassuiot/lamassuiot/pkg/utils"
	"github.com/lamassuiot/lamassuiot/pkg/utils/server/filters"
	"github.com/opentracing/opentracing-go"
)

type serviceSetUp struct {
	secrets secrets.Secrets
}

func TestSignCertificate(t *testing.T) {
	srv, ctx := setup(t)

	caType, _ := dto.ParseCAType("pki")
	caName := "testDCMock"
	certReq := testCA(caName)

	keyMetadata := dto.PrivateKeyMetadata{
		KeyType: certReq.KeyMetadata.KeyType,
		KeyBits: certReq.KeyMetadata.KeyBits,
	}
	newCA, _ := srv.CreateCA(ctx, caType, "testDCMock", keyMetadata, certReq.Subject, certReq.CaTTL, certReq.EnrollerTTL)
	input := "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ2pqQ0NBWFlDQVFBd1NURUxNQWtHQTFVRUJoTUNSVk14Q2pBSUJnTlZCQWdNQVVFeENqQUlCZ05WQkFjTQpBVUV4Q2pBSUJnTlZCQW9NQVVFeENqQUlCZ05WQkFzTUFVRXhDakFJQmdOVkJBTU1BVUV3Z2dFaU1BMEdDU3FHClNJYjNEUUVCQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUURDaFUxRFROckI0a2JTaVpjQjBMaHhUQ2dPYXlQUUU0VzkKT2N1MFBpczBybUliZnM2T2pERk5qcUY5dlhOcFlUSGhtL3FaTVZTWEZYZjM4VDBJS3NmU2lCYm5aa0pYWWc0NgptY2tLY1VkQ0VsUy8wK3RYaDh6Slo3QXNsV0Z2eXFLek5nUVJCcnhJQ0RVOTdVWXJ6eWk3ajVOSUJ2OHJvRld4CjVJOUNXUEpEQ00vRUFHMHVldjZQNVQzN2dKUzlFcnZXeERmWDVJL3hxRnZEQnpsV0VqbytFZ1piM3daSEt5d3QKMUVaVHBET1NKY29VeXZnWmFwUFF6U2JDZVdUL3ZlRW8rem5pUlk5SThFRlJhNm9DWDNCbVc4Snh2V2FSOVd3YQpnVUZ4cFM5OHdJN0JwSVJUeFgwdk9oMXZlUlBjWmRsVmFMZlJQb1BuV1BkdHAwckFDdXB6QWdNQkFBR2dBREFOCkJna3Foa2lHOXcwQkFRc0ZBQU9DQVFFQUllbTV5YnpVR1VvSk9yUjc1bW5COGZNUmVBWi9NalRVamYwem0xQjQKeGo4U1FMYTI2djU2ZkxOYkZ6NTlaaDlJa0J2U1AyNWNRTm5JU1lZT3RxejZLakJzcEVVQnNKaFVKcTNRNXpybgo3WVVoZnN2NWIzN0h2Y3h6akpvWW05NlZiU2FwQk5RWStGbjJ3R3NhZ1Zucktoalk0REdMM0lKQmlicmJvcEg2ClJwaFJRMWwyeXcwbUEybG9jK0hEZ1VwVTR4bXRpangvbHZmdHkzYVdwelBmV3pOWFRVYkEwNTFGY3hEQWh0SlkKbEd5WUxKSk1XQ08rL3NlUkxLSWFrZTFNeFR5Nzd0WVJ3MUNkVkJWWWFIbU8xM2k3ek8zYWVxdzloaGNHcWhyUQpXSWlYQ2lRdm9GN25oSmRvOEdmbkV5L1hKWk54LzQzbFVxUFcrekNhaWlsa2h3PT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUgUkVRVUVTVC0tLS0t"
	data, _ := base64.StdEncoding.DecodeString(input)
	block, _ := pem.Decode([]byte(data))
	csr, _ := x509.ParseCertificateRequest(block.Bytes)

	inputError := "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ3B6Q0NBWThDQVFBd1lqRUxNQWtHQTFVRUJoTUNSVk14RVRBUEJnTlZCQWdNQ0VkcGNIVjZhMjloTVJFdwpEd1lEVlFRSERBaEJjbkpoYzJGMFpURU1NQW9HQTFVRUNnd0RTVXRNTVF3d0NnWURWUVFMREFOYVVFUXhFVEFQCkJnTlZCQU1NQ0dWeWNtOXlURzluTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUEKMnZEckt0Y04yMTdjL09LSjhoYldyZmN4Y0ovWXE5NEdJZm8zOXozSERLK3hRaW1MQU42RnBFclNZS2lYKy96TApURzQzOUFaOXlCUko5cVlRZkFtaGlpcDdVbXdSeVA0QUpkN0hJTHVwUnZkOXNFVVhYM1BtUkc3UUVWQk9PbjhmClJmSFlFSDBYQnl0UEpPQkZpSGFOWUpGOG40RmJHWklPWWt2QVYvUWFVUEpONTBDc0xDYmJLTjRHRUk2c01CbEcKZkFNMHFFeGNJZ01lWFJKVHRDajZFOGU2cDNqRWFBTVJWTktFdFFUS2hYeWNQQjhLQnp5NmJEZVZCeUVQVHBaVQo0ZC9HYVBRdDVtVGc0T0Q4WXMyQjlocFlDZWtPYkZld29lL013dTVLNjZOZTNqZkdKbUFycGc5OGczcjVBNVBDCnphTWkxWjlnQlBrdzdiL2tEd0xKUHdJREFRQUJvQUF3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUtydUI0Sy8KY1IzOFN4S3BvL0w3WlpTQjJITTF0Mm4rdGhCUXAzZ0xVVnN4d2NWc3IvNGdRUjVCMzNOTml4TXBPbE51YitINgpaZiszaGpRVXpnc0RFa3c0aGgxSjZJdEdiQ0F6clVET2ZTbkNXMmRBZElWNWFkUk1lQTVSTWtIcmRrTFk0cm5vCnZEelRZTUlLYzJHMG9Qd2JnTnBNQm8zUmR0a0xCOG9mLy82dVptbkFXU1BOdkVZamJydkF3ZHgzOERWS1NPbUwKK3dKYXBEY0YxTlpBeWVkTlZVUUdiME9yeVovdXQzcXJ1VVM0QVg1bmVLRUg4eFFhUVNFOVM1UVJrT2tnZGlQNQpCNTdEMEc2emR4MkVOcmtkeXpyZUQ3cjc1R2ltWnRFaWxRUDBWd1o0SkhJbnRmb21oSzFuSXplM1U5ZnZ4ZmVjCkhZMzlWUXJyZU9RRjdKYz0KLS0tLS1FTkQgQ0VSVElGSUNBVEUgUkVRVUVTVC0tLS0t"
	dataError, _ := base64.StdEncoding.DecodeString(inputError)
	blockError, _ := pem.Decode([]byte(dataError))
	csrError, _ := x509.ParseCertificateRequest(blockError.Bytes)

	testCases := []struct {
		name string
		in   *x509.CertificateRequest
		ret  error
	}{

		{"Incorrect", csrError, errors.New("TEST: Could not obtain list of Vault mounts")},
		{"Correct", csr, nil},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {
			if tc.name == "Incorrect" {
				ctx = context.WithValue(ctx, "DBIncorrect", true)
			} else {
				ctx = context.WithValue(ctx, "DBIncorrect", false)
			}
			_, err := srv.SignCertificate(ctx, caType, newCA.Name, *tc.in, false, tc.in.Subject.CommonName)

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

func TestStats(t *testing.T) {
	srv, ctx := setup(t)
	caType, _ := dto.ParseCAType("pki")
	certReq := testCA("testDCMock")
	keyMetadata := dto.PrivateKeyMetadata{
		KeyType: certReq.KeyMetadata.KeyType,
		KeyBits: certReq.KeyMetadata.KeyBits,
	}
	newCA, _ := srv.CreateCA(ctx, caType, "testDCMock", keyMetadata, certReq.Subject, certReq.CaTTL, certReq.EnrollerTTL)

	data, _ := base64.StdEncoding.DecodeString("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ2pqQ0NBWFlDQVFBd1NURUxNQWtHQTFVRUJoTUNSVk14Q2pBSUJnTlZCQWdNQVVFeENqQUlCZ05WQkFjTQpBVUV4Q2pBSUJnTlZCQW9NQVVFeENqQUlCZ05WQkFzTUFVRXhDakFJQmdOVkJBTU1BVUV3Z2dFaU1BMEdDU3FHClNJYjNEUUVCQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUURDaFUxRFROckI0a2JTaVpjQjBMaHhUQ2dPYXlQUUU0VzkKT2N1MFBpczBybUliZnM2T2pERk5qcUY5dlhOcFlUSGhtL3FaTVZTWEZYZjM4VDBJS3NmU2lCYm5aa0pYWWc0NgptY2tLY1VkQ0VsUy8wK3RYaDh6Slo3QXNsV0Z2eXFLek5nUVJCcnhJQ0RVOTdVWXJ6eWk3ajVOSUJ2OHJvRld4CjVJOUNXUEpEQ00vRUFHMHVldjZQNVQzN2dKUzlFcnZXeERmWDVJL3hxRnZEQnpsV0VqbytFZ1piM3daSEt5d3QKMUVaVHBET1NKY29VeXZnWmFwUFF6U2JDZVdUL3ZlRW8rem5pUlk5SThFRlJhNm9DWDNCbVc4Snh2V2FSOVd3YQpnVUZ4cFM5OHdJN0JwSVJUeFgwdk9oMXZlUlBjWmRsVmFMZlJQb1BuV1BkdHAwckFDdXB6QWdNQkFBR2dBREFOCkJna3Foa2lHOXcwQkFRc0ZBQU9DQVFFQUllbTV5YnpVR1VvSk9yUjc1bW5COGZNUmVBWi9NalRVamYwem0xQjQKeGo4U1FMYTI2djU2ZkxOYkZ6NTlaaDlJa0J2U1AyNWNRTm5JU1lZT3RxejZLakJzcEVVQnNKaFVKcTNRNXpybgo3WVVoZnN2NWIzN0h2Y3h6akpvWW05NlZiU2FwQk5RWStGbjJ3R3NhZ1Zucktoalk0REdMM0lKQmlicmJvcEg2ClJwaFJRMWwyeXcwbUEybG9jK0hEZ1VwVTR4bXRpangvbHZmdHkzYVdwelBmV3pOWFRVYkEwNTFGY3hEQWh0SlkKbEd5WUxKSk1XQ08rL3NlUkxLSWFrZTFNeFR5Nzd0WVJ3MUNkVkJWWWFIbU8xM2k3ek8zYWVxdzloaGNHcWhyUQpXSWlYQ2lRdm9GN25oSmRvOEdmbkV5L1hKWk54LzQzbFVxUFcrekNhaWlsa2h3PT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUgUkVRVUVTVC0tLS0t")
	block, _ := pem.Decode([]byte(data))
	csr, _ := x509.ParseCertificateRequest(block.Bytes)

	srv.SignCertificate(ctx, caType, newCA.Name, *csr, false)

	var caList []dto.Cert
	caList = append(caList, newCA)
	testCases := []struct {
		name string
		err  error
	}{
		{"Correct", nil},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {
			stats := srv.Stats(ctx)
			if stats.CAs == 0 {
				t.Errorf("Error")
			}
		})
	}
}
func TestGetSecretProviderName(t *testing.T) {
	srv, ctx := setup(t)

	testCases := []struct {
		name string
		ret  string
	}{
		{"Correct", "Hashicorp_Vault"},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {
			out := srv.GetSecretProviderName(ctx)
			if tc.ret != out {
				t.Errorf("Secret Provider Name error")
			}
		})
	}
}

func TestGetCAs(t *testing.T) {
	srv, ctx := setup(t)

	caType, _ := dto.ParseCAType("pki")
	var caList []dto.Cert
	var caEmptyList []dto.Cert
	certReq := testCA("testDCMock")
	keyMetadata := dto.PrivateKeyMetadata{
		KeyType: certReq.KeyMetadata.KeyType,
		KeyBits: certReq.KeyMetadata.KeyBits,
	}
	ca, _ := srv.CreateCA(ctx, caType, certReq.Name, keyMetadata, certReq.Subject, certReq.CaTTL, certReq.EnrollerTTL)
	caList = append(caList, ca)

	testCases := []struct {
		name string
		res  []dto.Cert
		ret  error
	}{

		{"Correct", caList, nil},
		{"Incorrect", caEmptyList, errors.New("TEST: Could not obtain list of Vault mounts")},
	}
	for _, tc := range testCases {

		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {
			if tc.name == "Incorrect" {
				ctx = context.WithValue(ctx, "DBIncorrect", true)
			}
			_, err := srv.GetCAs(ctx, caType)
			if err != nil {
				if err.Error() != tc.ret.Error() {
					t.Errorf("Got result is %s; want %s", err, tc.ret)
				}
			}
		})
	}
}
func TestImportCA(t *testing.T) {
	srv, ctx := setup(t)

	caType, _ := dto.ParseCAType("pki")
	s := "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUZvekNDQTR1Z0F3SUJBZ0lVSFRQSG56Y05ybFZwOHhMWi80NGFZSS9hdElRd0RRWUpLb1pJaHZjTkFRRUwKQlFBd1lURUxNQWtHQTFVRUJoTUNSVk14RVRBUEJnTlZCQWdNQ0VkcGNIVjZhMjloTVJFd0R3WURWUVFIREFoQgpjbkpoYzJGMFpURU1NQW9HQTFVRUNnd0RTVXRNTVF3d0NnWURWUVFMREFOYVVFUXhFREFPQmdOVkJBTU1CME5CCklFTkZVbFF3SGhjTk1qSXdNakUzTURjME1EQTFXaGNOTWpNd01qRTNNRGMwTURBMVdqQmhNUXN3Q1FZRFZRUUcKRXdKRlV6RVJNQThHQTFVRUNBd0lSMmx3ZFhwcmIyRXhFVEFQQmdOVkJBY01DRUZ5Y21GellYUmxNUXd3Q2dZRApWUVFLREFOSlMwd3hEREFLQmdOVkJBc01BMXBRUkRFUU1BNEdBMVVFQXd3SFEwRWdRMFZTVkRDQ0FpSXdEUVlKCktvWklodmNOQVFFQkJRQURnZ0lQQURDQ0Fnb0NnZ0lCQU1kRTJQeWRRT1ZQS3pkcDNMdXZMNEsybkpkMXFlYXgKZFdUY0REZXVnK1pHNDJCd0krUVd0SHZVYWhlcU9nR3cvcEwwUkp4TDBqNGU4dS9UTlFGazhwYlUxRW9vYk5BNgovK1JoQkcyWkp4ZWJYcFlPQ2VTNzFTeEpqT1lwQmFwRVA2OE80UThoei9Pa3AxM3crOHZoL214SExqK0E4Z204CkFwUUt0emFiY2x6NUFxN0pFQ2VMdmg1WEsvNnVtOVg1N2pGYTlLNFBrcUtLSWEyWkxzUG1vOElVV3NWT3JxMkMKVjRhS3Z6L2tUeENGc29mblBBOW5CVGdOamFSd1dxUDBmM25VZDFrcElnME8rbUFkck10MVZzN1I0STB1M0xDRgpOSCtKOTdvQUdXU3dyMmtVQzZKTm1TdklKYW5BclNqMGtJZjBNUDlSSHNDRmplQ1p3S1J1UUlTMk1HLzE1VFV5CmRFZDI0aHpWSUlaZ1RZZ0pCaFZVNnlMSk92eStreEswTTlKUkduc0tYY1R3SldCT2JFUnFNaEJVc0d1QUl6RFoKYU5ycjl6UVArOU9XZXFmT29OOE4zejBMRk4xZEs3R1BGd2hXc1FYMCtYenFrbElHaWEyUHI0ODk5K0k0ZGJyVwpGYXp1TTMwTng3OGhKQ25SR3RxQ0lJZldydGVVRDRicncvejV6THpwY3RTZ3owM0RnTFJnUHBIaEJoby8zVEt5CkxQOWZ4TW4wQ2I2bXdvZ3g0NUVsSk8rYURkNFIrbVQrYlFZdWRlcVd3NWdLeTJnR1gwTnJEVVFZRTFTQlpyS1gKd0VWOWFhL0craFZxOGRhTFJBYlF0bVlQN2lxU3FUaWZBZlVkeTdnYnFXZUxWWFowd3h1YlhmSHhpT0ZsV1ZudQo1bXlpcFFPRmNUbk5BZ01CQUFHalV6QlJNQjBHQTFVZERnUVdCQlRkcE9jMXZjRFJpYkN3d1NlTjgxWUVoK3lPCnpEQWZCZ05WSFNNRUdEQVdnQlRkcE9jMXZjRFJpYkN3d1NlTjgxWUVoK3lPekRBUEJnTlZIUk1CQWY4RUJUQUQKQVFIL01BMEdDU3FHU0liM0RRRUJDd1VBQTRJQ0FRQ3JEQUZ2dnhRTkdCaGw4bGZ6YnBGaDBRTFZoNVM0UHpOTwpDUEp6ZDlFQnJiYVQ4SHZLbHhUV3BicEFkQkZqaTJPYWRlRjkwT1dCcHNhaDlvVUd1VnN4Q0hsMnhPL1dRWDR0Ck94ODY5ekprc0o4OUNjQWY3ZVFvbjRpV1krMjZFeGo3Q05obFB0ZDQwOW5YN2N4UlBxQWw0d0hKeEpGUFlLeEEKdzY4SUdRaVpmcFZ6VldzYU00S2w3Q2poS05SdlEyMThpd244amRLWlN5YnczRlI2NTB1Ui9YOFFCNUZIQVRXZgpjbjVVQzI0bXFGckFWdWN1eFRFdGNqalFXeGZaNmRBaDJJdFlMVE5NbU9ERG1pZzU2Q1JwMHRrOExrekMzRmVBCk1UZTJwQnR3alNmazZYd05zK0RIMngvbU9kSFBFR0ZJYUlXQ3FtWUtxYmdwU1MwVVczak5pZ2ZjaWF1RWpkalQKaTJVMXhLS0labXY4V2xEOGM1bklOcTd4SzJZU0VJR2tNTVIyNjQ5UzN0TFBRYit2UkJxWW5rUjdhbFdhZkNUWgpiMFY3U2NIallPR2NRcXJmU1RsS041b1ptZWI3M2U2eW9uUEVFY2NqTTB0Uk9vMmpUMkwvQUVEU1pUVU91K084Cmxmcm41UEFXMDhzUEJIR1pUSGhuUzVMRUYydVlhdkdNMkM0cEVwQ2tMR3ltd1RxYWJ5MG9GejN5Uzg5YlV4R1EKbkZDR1IrbXRTaW1tTFNOdWR2cjRkK3NweDE4RzVETlZ0TEJ0b2NyRnhwZWRzS2JmaXQrQi95MytjWW1EL0RZYQo2QU92TGJZN3hXT3JwZnJHOXVqa3hvYzZKbjBpL3V2QkhJOEVNTlp1dUVDa2Y0MlUvbXdpMFdFcVBJdjRwN0lNClh2Y3lnUFZvTmc9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0t"
	data, _ := base64.StdEncoding.DecodeString(s)
	block, _ := pem.Decode([]byte(data))
	cert1, _ := x509.ParseCertificate(block.Bytes)

	testCases := []struct {
		name   string
		caName string
		cert   x509.Certificate
		ret    error
	}{
		{"Correct CA", "testImport", *cert1, nil},
		{"CA already exist", "testImport", *cert1, errors.New("resource already exists. resource_type=CA resource_id=testImport")},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {

			privateKeyStr := "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlKS2dJQkFBS0NBZ0VBeDBUWS9KMUE1VThyTjJuY3U2OHZncmFjbDNXcDVyRjFaTndNTjY2RDVrYmpZSEFqCjVCYTBlOVJxRjZvNkFiRCtrdlJFbkV2U1BoN3k3OU0xQVdUeWx0VFVTaWhzMERyLzVHRUViWmtuRjV0ZWxnNEoKNUx2VkxFbU01aWtGcWtRL3J3N2hEeUhQODZTblhmRDd5K0grYkVjdVA0RHlDYndDbEFxM05wdHlYUGtDcnNrUQpKNHUrSGxjci9xNmIxZm51TVZyMHJnK1Nvb29oclprdXcrYWp3aFJheFU2dXJZSlhob3EvUCtSUEVJV3loK2M4CkQyY0ZPQTJOcEhCYW8vUi9lZFIzV1NraURRNzZZQjJzeTNWV3p0SGdqUzdjc0lVMGY0bjN1Z0FaWkxDdmFSUUwKb2syWks4Z2xxY0N0S1BTUWgvUXcvMUVld0lXTjRKbkFwRzVBaExZd2IvWGxOVEowUjNiaUhOVWdobUJOaUFrRwpGVlRySXNrNi9MNlRFclF6MGxFYWV3cGR4UEFsWUU1c1JHb3lFRlN3YTRBak1ObG8ydXYzTkEvNzA1WjZwODZnCjN3M2ZQUXNVM1YwcnNZOFhDRmF4QmZUNWZPcVNVZ2FKclkrdmp6MzM0amgxdXRZVnJPNHpmUTNIdnlFa0tkRWEKMm9JZ2g5YXUxNVFQaHV2RC9Qbk12T2x5MUtEUFRjT0F0R0Era2VFR0dqL2RNcklzLzEvRXlmUUp2cWJDaURIagprU1VrNzVvTjNoSDZaUDV0Qmk1MTZwYkRtQXJMYUFaZlEyc05SQmdUVklGbXNwZkFSWDFwcjhiNkZXcngxb3RFCkJ0QzJaZy91S3BLcE9KOEI5UjNMdUJ1cFo0dFZkblRERzV0ZDhmR0k0V1ZaV2U3bWJLS2xBNFZ4T2MwQ0F3RUEKQVFLQ0FnRUF0UVEzMFJMUTl2MzZGamFXaS9CU1NuMjB0bW51MDEvMWNvL3FrVko1QTJEMkFJOGVLMzdzcVdpRwpqOFRWT09BZUFrVGZadFFCd3VpK2Exb0QxcVpyTU5WWm01d3BiT2VMdVZ6Z2R1Y2ZlZlJyOGdnQ3VNUmduQUNjCmZDQmJ3eGFJZTNBYXhuSkN3K09aSGw5aGZRNW8zdGV5allHSFhZeHJFeXpBemx4YmdWVzdPQ2Z5QXRxUTlHTGYKMWxXcnZxOXh6MmYreVhmZ0RzTklZTGk4b0wwTm1hcC80cWpkU1VVVVdXWUU0ZmQyVTE0QWxqQmFnT3RtOUVwcgpseXR4UzJzNXVlUm1IcHFkRWh1L0dqMGEwU0Jnb1RSS3RqWVJ5RkRaSmRxaExWZ1Z1VUEvdUVhN1lzNzNDNnlmCmVodExzZDZveExmeElwNEFQNGVUSUtyTE14UHNpb1hMYTFvNXhCc2NCUmRGejZNNDRTODNSRWhLUGhKOFJuME8KZXlpVXFNeW9IVUMwd2JXeERMM1ZadjF3eUhiMXRLS2dVS0VMOGptS3FQV2dneWM4eUNONENEMWpXRUUwL1E5cwpYZGwycDNpMEJUL0M4Y3U5cUNOUGdMdFQ1MXE5d1EzNnpYOHZhbzQvdW5xbjZYWFptUmFud3lFYytwTmpiTFRWCmorL04xTE1HaXg0ZTNiZHFyb1dkR0g2VHlHUnF0MG9scU5hbTZiUDh2Y2x4QVVhMlVEU1J3dDdiSTRIQnVQeUQKNGYvQUNJMEpEbXo0cDFhVFdFclc0TVlydmM5YW50a3hKd1o3WTBQK0F3U1V3U1dPK1FYV09DRk5TeTlxcGRiQgpkb21LV0xlNk41ZXV2L1ErQm1VYUtMQnJzRUdwNTliam9uK2E2Z21FME5ONkZwc2c0UUVDZ2dFQkFQbUNobkU1Ck4vR21xZFM5OXZmYkp6UkZONFNmZVJSWVhtTnV2MWJ6OW5lOU5DazhkT0xkSFRmTnNiZm5nS1o2Yys2UGlpQW8KZjgzazJSNEF0WkVGSTZjaG5SZnlzNUduejg3WERNUTMxcXhyT1RsdjdYVDEwcERCWVA5NWVPNXRIWWVsSzRaWQp0Q2lqc2swMjMzZzlkYTRCeWw2amgvT0htTHNvL28vWkpvMVVlM0IvUmdtMXk0T3BQR29Fdi9tb0orUENscDN3ClIvMTE4Szh4VXkyTmhPYzExWE9tSHZtSHJMOG9mQ1JISVBCckZDMDB6cU9QUllDL0gvMHFnVTNHc0o4MmpRdG8KL1N6clNqVTdQTEkwcHNTWVA4d3RjOHBGNkt6dFNMSHVOaFdoQ3RodGRYdzhSdGgrQmI1NDRQbU5LYVJ5WEdNMQo4Wm11K25jNzhQTXQwS0VDZ2dFQkFNeHp4VGY0bVFnMnUvZ1VFZ0xENjcvUXJJR05Tc3diMy9TUWVnWEM3cmY1CmRlVWZKSFdRQ2ZiU1lwT1BweUxEM2l2WmtrR3BUWmhtTGYyaXVid1Z3eDdxRlpISGE5ODdxQ1Q0MCthUkNSakEKUEF0ZnNESGIxSVdPMXp0ejJqSmh4bndjQk9OZStSVUlWUGkzQ2o5dVlCNWI4V25RWEdjUUJ6WnFEckZNc1EwMQo2ejhLWWxHR1pqVi9UNUtvR29RQStyNHg1WnFVL3dZdW9uQnNuVFhrb0k4WXZJdHIvUUhKWGpZSElKR3lLZW9SCndUTDFXNkR3OURIdlJDY2RlQjA0NUhPa1l4MitUUTZ6cjZaZSt6R3F5Vm9VSkpsWVBpZnlQQWwwRExnbzc0VjgKdjREQ1c5TlJ6V2o5YVNacXMwQnRVTU80YTJycWk0Z0Z3TUdibEtzNUhhMENnZ0VCQUsvMWx1NStWYSs3dzRWZQp1cTZ0QlFiZDBYdGNJNzF2WEpGdTVzMWhtMjF5SnpqMWc5RUI4cnNKK3MwaEhCOUx1RHFEUy92RjArdlYrakFvCmUrTmI1bnJWUDc1RjBORmxzUzNEaHlOUjVia09uUHFlcnEyUE53SVMvbDdzd1pZVHFZR2h3QUlzeUZEb3NMTzMKZ1AyQkNsNitzSUx4Zk0wSDBYUWNRdm9iUUE3bmgyNGNzNzNoVVRiMndMNWJ2eTlIb1dvRUxzZ1BUaFczZVJkMApCNTdXY09YRmwxVEowSXBWWGtRcFB2TXVubEl1a2JvWHhhcWZQWHJBVHNUeGx1TE12bjVwc0NwZHpqNUJhTUlGCmxwWnVmeldoMFV3aXVjZnFhVjZhc0d1YS9OVmdEdy8ya2FZZHREQzFIMFBtWjNKV1ZRbStCTjJLaTJuQWRxNWoKdlZjaDlrRUNnZ0VCQUlPMjdjNkNSS3lxL212ekdpdFg1eEE3TW5kLy9Ea0VtRUpwdFlMeXMzSW9yMUE5d1BKUQpLbXN0M0wzdDVTSWJoNDArYk9BS1gyZ1lJL2JzRjdaWldzd1d5SENUUmlhWnUxaWVTWDJYNElGbWp3aFF6Q1ZDCjEyWjN3S2VYbW5HczFmOXMyYVZWc1NoZ3BzVll2cXhnd21Hc29CbW9WMjg2UHp0S0ZrOFk5bE5wY2pXNXpkOXgKczNVeG9LVDkwWjlMTmo3RHpJVExDb1VFRkRoVGNQQ2dhdVBsYnNwdmRwN3BDTjNMdDZyRldnVm5ETTEwam1SZgo5eUlZWUJMSEJIUG5EQjZJUUNhUVMvcDF2bXB6ZEdicC9UQWdHL2dDaG9DYnFSdjUvSnZFRzVNbTdBVGFzZWV4CklxRko2SzBNUHBENkcvY0xYNENRdS9XVXB6clRyWEtscUQwQ2dnRUFWTmdqVFJWaHlGNkYvOTB2bS9LZVd2TlQKQ2E3Y0R2TW5rT21VeFo2eUdpZmlTM2wrY1pHbDJlNXhXM2Njb3ZmWkhnU20vd21sQzFWbHZTREsrdzdOMEpXcwo0cC84c0d2YnN3L0lmTUR5N0cydXdzSzZsSDBlTyszODdDZUpwNmZCNjFRNnZhdFVMbGZXSi9sVVBDTGhMenNmClZiSERFQzlIWHFvK1lYZTZpSGNkYnozcDAwVGx5VEpRMHhZVnRwdklTdkR4WHl1WFpsUHlrSXVvaGtIM0RmTEcKQjgvcDFBb3dYVmhuT0FMclk5dC9SMXVnYjBNQnhWT3BpTk5qckN0bnpUQXRRKzc5Rm1hMVd2STdKVmdaZUxrVwp5WXFPb0JoUDJ6eGExY01ubUV0dXBmcEJiRGxQbFRzYXZZM0RVVXBCYVJtOWozb2RtSElidmpYVElPb3ptQT09Ci0tLS0tRU5EIFJTQSBQUklWQVRFIEtFWS0tLS0t"
			privateKeyData, _ := base64.StdEncoding.DecodeString(privateKeyStr)
			privateKeyBlock, _ := pem.Decode([]byte(privateKeyData))
			rsaKey, err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)

			keyM := dto.PrivateKey{
				KeyType: dto.RSA,
				Key:     rsaKey,
			}

			_, err = srv.ImportCA(ctx, caType, tc.caName, tc.cert, keyM, 1000)
			if tc.ret != nil {
				if err != nil {
					if err.Error() != tc.ret.Error() {
						t.Errorf("Got result is %s; want %s", err, tc.ret)
					}
				}
			}

		})
	}
}

func TestGetCert(t *testing.T) {
	srv, ctx := setup(t)

	caType, _ := dto.ParseCAType("pki")
	caName := "testMockGetCert"
	certReq := testCA(caName)
	certEmptySN := testCA(caName)
	certEmptySN.SerialNumber = ""

	keyMetadata := dto.PrivateKeyMetadata{
		KeyType: certReq.KeyMetadata.KeyType,
		KeyBits: certReq.KeyMetadata.KeyBits,
	}
	newCert, _ := srv.CreateCA(ctx, caType, caName, keyMetadata, certReq.Subject, certReq.CaTTL, certEmptySN.EnrollerTTL)

	testCases := []struct {
		name string
		cert dto.Cert
		ret  dto.Cert
		err  error
	}{
		{"Correct", newCert, newCert, nil},
		{"Empty serial number", certEmptySN, dto.Cert{}, errors.New("empty serial number")},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {
			out, err := srv.GetCert(ctx, caType, tc.cert.Name, tc.cert.SerialNumber)
			if err != nil {
				if err.Error() != tc.err.Error() {
					t.Errorf("Got result is %s; want %s", err, tc.err)
				}
			} else {
				if out != tc.ret {
					t.Errorf("Got result is %s; want %s", out.SerialNumber, tc.ret.SerialNumber)
				}
			}
		})
	}
}

func TestGetIssuedCerts(t *testing.T) {
	srv, ctx := setup(t)

	caType, _ := dto.ParseCAType("pki")
	certReq := testCA("testDCMock")
	keyMetadata := dto.PrivateKeyMetadata{
		KeyType: certReq.KeyMetadata.KeyType,
		KeyBits: certReq.KeyMetadata.KeyBits,
	}
	newCA, _ := srv.CreateCA(ctx, caType, "testDCMock", keyMetadata, certReq.Subject, certReq.CaTTL, certReq.EnrollerTTL)

	data, _ := base64.StdEncoding.DecodeString("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ2pqQ0NBWFlDQVFBd1NURUxNQWtHQTFVRUJoTUNSVk14Q2pBSUJnTlZCQWdNQVVFeENqQUlCZ05WQkFjTQpBVUV4Q2pBSUJnTlZCQW9NQVVFeENqQUlCZ05WQkFzTUFVRXhDakFJQmdOVkJBTU1BVUV3Z2dFaU1BMEdDU3FHClNJYjNEUUVCQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUURDaFUxRFROckI0a2JTaVpjQjBMaHhUQ2dPYXlQUUU0VzkKT2N1MFBpczBybUliZnM2T2pERk5qcUY5dlhOcFlUSGhtL3FaTVZTWEZYZjM4VDBJS3NmU2lCYm5aa0pYWWc0NgptY2tLY1VkQ0VsUy8wK3RYaDh6Slo3QXNsV0Z2eXFLek5nUVJCcnhJQ0RVOTdVWXJ6eWk3ajVOSUJ2OHJvRld4CjVJOUNXUEpEQ00vRUFHMHVldjZQNVQzN2dKUzlFcnZXeERmWDVJL3hxRnZEQnpsV0VqbytFZ1piM3daSEt5d3QKMUVaVHBET1NKY29VeXZnWmFwUFF6U2JDZVdUL3ZlRW8rem5pUlk5SThFRlJhNm9DWDNCbVc4Snh2V2FSOVd3YQpnVUZ4cFM5OHdJN0JwSVJUeFgwdk9oMXZlUlBjWmRsVmFMZlJQb1BuV1BkdHAwckFDdXB6QWdNQkFBR2dBREFOCkJna3Foa2lHOXcwQkFRc0ZBQU9DQVFFQUllbTV5YnpVR1VvSk9yUjc1bW5COGZNUmVBWi9NalRVamYwem0xQjQKeGo4U1FMYTI2djU2ZkxOYkZ6NTlaaDlJa0J2U1AyNWNRTm5JU1lZT3RxejZLakJzcEVVQnNKaFVKcTNRNXpybgo3WVVoZnN2NWIzN0h2Y3h6akpvWW05NlZiU2FwQk5RWStGbjJ3R3NhZ1Zucktoalk0REdMM0lKQmlicmJvcEg2ClJwaFJRMWwyeXcwbUEybG9jK0hEZ1VwVTR4bXRpangvbHZmdHkzYVdwelBmV3pOWFRVYkEwNTFGY3hEQWh0SlkKbEd5WUxKSk1XQ08rL3NlUkxLSWFrZTFNeFR5Nzd0WVJ3MUNkVkJWWWFIbU8xM2k3ek8zYWVxdzloaGNHcWhyUQpXSWlYQ2lRdm9GN25oSmRvOEdmbkV5L1hKWk54LzQzbFVxUFcrekNhaWlsa2h3PT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUgUkVRVUVTVC0tLS0t")
	block, _ := pem.Decode([]byte(data))
	csr, _ := x509.ParseCertificateRequest(block.Bytes)

	srv.SignCertificate(ctx, caType, newCA.Name, *csr, false, csr.Subject.CommonName)

	var caList []dto.Cert
	caList = append(caList, newCA)

	var CAEmptys []dto.Cert

	testCases := []struct {
		name string
		res  []dto.Cert
		ret  error
	}{

		{"Correct", caList, nil},
		{"Incorrect", CAEmptys, errors.New("TEST: Could not obtain list of Vault mounts")},
	}
	for _, tc := range testCases {

		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {
			if tc.name == "Incorrect" {
				ctx = context.WithValue(ctx, "DBIncorrect", true)
			}
			_, _, err := srv.GetIssuedCerts(ctx, caType, newCA.Name, filters.QueryParameters{})
			if err != nil {
				if err.Error() != tc.ret.Error() {
					t.Errorf("Got result is %s; want %s", err, tc.ret)
				}
			}
		})
	}
}

func TestCreateCA(t *testing.T) {
	srv, ctx := setup(t)

	caNameC := "FUYF"
	certReq := testCA(caNameC)
	caType, _ := dto.ParseCAType("pki")

	testCases := []struct {
		name    string
		newCert dto.Cert
		ret     dto.Cert
		err     error
	}{
		{"Correct CA", certReq, certReq, nil},
		{"Create empty", dto.Cert{}, dto.Cert{}, errors.New("resource already exists. resource_type=CA resource_id=")},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {
			keyMetadata := dto.PrivateKeyMetadata{
				KeyType: certReq.KeyMetadata.KeyType,
				KeyBits: certReq.KeyMetadata.KeyBits,
			}
			_, err := srv.CreateCA(ctx, caType, tc.newCert.Name, keyMetadata, certReq.Subject, certReq.CaTTL, certReq.EnrollerTTL)
			if tc.ret != tc.newCert {
				t.Errorf("Got result is different of created CA")
			}
			if err != nil {
				if err.Error() != tc.err.Error() {
					t.Errorf("Got result is %s; want %s", err, tc.err)
				}
			}
			if err == nil {
				err = srv.DeleteCA(ctx, caType, tc.newCert.Name)
				if err != nil {
					t.Fatal("Could not delete CA from DB")
				}
			}
		})
	}
}

func TestDeleteCA(t *testing.T) {
	srv, ctx := setup(t)

	caType, err := dto.ParseCAType("pki")
	caNameC := "testDeleteCA"
	certReq := testCA(caNameC)
	keyMetadata := dto.PrivateKeyMetadata{
		KeyType: certReq.KeyMetadata.KeyType,
		KeyBits: certReq.KeyMetadata.KeyBits,
	}
	newCA, _ := srv.CreateCA(ctx, caType, caNameC, keyMetadata, certReq.Subject, certReq.CaTTL, certReq.EnrollerTTL)

	data, _ := base64.StdEncoding.DecodeString("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ2pqQ0NBWFlDQVFBd1NURUxNQWtHQTFVRUJoTUNSVk14Q2pBSUJnTlZCQWdNQVVFeENqQUlCZ05WQkFjTQpBVUV4Q2pBSUJnTlZCQW9NQVVFeENqQUlCZ05WQkFzTUFVRXhDakFJQmdOVkJBTU1BVUV3Z2dFaU1BMEdDU3FHClNJYjNEUUVCQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUURDaFUxRFROckI0a2JTaVpjQjBMaHhUQ2dPYXlQUUU0VzkKT2N1MFBpczBybUliZnM2T2pERk5qcUY5dlhOcFlUSGhtL3FaTVZTWEZYZjM4VDBJS3NmU2lCYm5aa0pYWWc0NgptY2tLY1VkQ0VsUy8wK3RYaDh6Slo3QXNsV0Z2eXFLek5nUVJCcnhJQ0RVOTdVWXJ6eWk3ajVOSUJ2OHJvRld4CjVJOUNXUEpEQ00vRUFHMHVldjZQNVQzN2dKUzlFcnZXeERmWDVJL3hxRnZEQnpsV0VqbytFZ1piM3daSEt5d3QKMUVaVHBET1NKY29VeXZnWmFwUFF6U2JDZVdUL3ZlRW8rem5pUlk5SThFRlJhNm9DWDNCbVc4Snh2V2FSOVd3YQpnVUZ4cFM5OHdJN0JwSVJUeFgwdk9oMXZlUlBjWmRsVmFMZlJQb1BuV1BkdHAwckFDdXB6QWdNQkFBR2dBREFOCkJna3Foa2lHOXcwQkFRc0ZBQU9DQVFFQUllbTV5YnpVR1VvSk9yUjc1bW5COGZNUmVBWi9NalRVamYwem0xQjQKeGo4U1FMYTI2djU2ZkxOYkZ6NTlaaDlJa0J2U1AyNWNRTm5JU1lZT3RxejZLakJzcEVVQnNKaFVKcTNRNXpybgo3WVVoZnN2NWIzN0h2Y3h6akpvWW05NlZiU2FwQk5RWStGbjJ3R3NhZ1Zucktoalk0REdMM0lKQmlicmJvcEg2ClJwaFJRMWwyeXcwbUEybG9jK0hEZ1VwVTR4bXRpangvbHZmdHkzYVdwelBmV3pOWFRVYkEwNTFGY3hEQWh0SlkKbEd5WUxKSk1XQ08rL3NlUkxLSWFrZTFNeFR5Nzd0WVJ3MUNkVkJWWWFIbU8xM2k3ek8zYWVxdzloaGNHcWhyUQpXSWlYQ2lRdm9GN25oSmRvOEdmbkV5L1hKWk54LzQzbFVxUFcrekNhaWlsa2h3PT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUgUkVRVUVTVC0tLS0t")
	block, _ := pem.Decode([]byte(data))
	csr, _ := x509.ParseCertificateRequest(block.Bytes)

	srv.SignCertificate(ctx, caType, "testDeleteCA", *csr, false, csr.Subject.CommonName)

	if err != nil {
		t.Fatal("Could not insert CA in DB")
	}

	testCases := []struct {
		name string
		cert dto.Cert
		ret  error
	}{
		{"Delete not existing CA", testCA("notExists"), errors.New("could not delete certificate from Vault")},
		{"Delete CA ", newCA, nil},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {

			err = srv.DeleteCA(ctx, caType, tc.cert.Name)
			if err != nil {
				if err.Error() != tc.ret.Error() {
					t.Errorf("Got result is %s; want %s", err, tc.ret)
				}
			}
		})
	}
	if err != nil {
		t.Fatal("Could not delete CA from file system")
	}
}

func TestDeleteCert(t *testing.T) {
	srv, ctx := setup(t)

	caType, _ := dto.ParseCAType("pki")
	certReq := testCA("testDCMockc")
	keyMetadata := dto.PrivateKeyMetadata{
		KeyType: certReq.KeyMetadata.KeyType,
		KeyBits: certReq.KeyMetadata.KeyBits,
	}
	newCA, err := srv.CreateCA(ctx, caType, "testDCMockc", keyMetadata, certReq.Subject, certReq.CaTTL, certReq.EnrollerTTL)

	data, _ := base64.StdEncoding.DecodeString("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ2pqQ0NBWFlDQVFBd1NURUxNQWtHQTFVRUJoTUNSVk14Q2pBSUJnTlZCQWdNQVVFeENqQUlCZ05WQkFjTQpBVUV4Q2pBSUJnTlZCQW9NQVVFeENqQUlCZ05WQkFzTUFVRXhDakFJQmdOVkJBTU1BVUV3Z2dFaU1BMEdDU3FHClNJYjNEUUVCQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUURDaFUxRFROckI0a2JTaVpjQjBMaHhUQ2dPYXlQUUU0VzkKT2N1MFBpczBybUliZnM2T2pERk5qcUY5dlhOcFlUSGhtL3FaTVZTWEZYZjM4VDBJS3NmU2lCYm5aa0pYWWc0NgptY2tLY1VkQ0VsUy8wK3RYaDh6Slo3QXNsV0Z2eXFLek5nUVJCcnhJQ0RVOTdVWXJ6eWk3ajVOSUJ2OHJvRld4CjVJOUNXUEpEQ00vRUFHMHVldjZQNVQzN2dKUzlFcnZXeERmWDVJL3hxRnZEQnpsV0VqbytFZ1piM3daSEt5d3QKMUVaVHBET1NKY29VeXZnWmFwUFF6U2JDZVdUL3ZlRW8rem5pUlk5SThFRlJhNm9DWDNCbVc4Snh2V2FSOVd3YQpnVUZ4cFM5OHdJN0JwSVJUeFgwdk9oMXZlUlBjWmRsVmFMZlJQb1BuV1BkdHAwckFDdXB6QWdNQkFBR2dBREFOCkJna3Foa2lHOXcwQkFRc0ZBQU9DQVFFQUllbTV5YnpVR1VvSk9yUjc1bW5COGZNUmVBWi9NalRVamYwem0xQjQKeGo4U1FMYTI2djU2ZkxOYkZ6NTlaaDlJa0J2U1AyNWNRTm5JU1lZT3RxejZLakJzcEVVQnNKaFVKcTNRNXpybgo3WVVoZnN2NWIzN0h2Y3h6akpvWW05NlZiU2FwQk5RWStGbjJ3R3NhZ1Zucktoalk0REdMM0lKQmlicmJvcEg2ClJwaFJRMWwyeXcwbUEybG9jK0hEZ1VwVTR4bXRpangvbHZmdHkzYVdwelBmV3pOWFRVYkEwNTFGY3hEQWh0SlkKbEd5WUxKSk1XQ08rL3NlUkxLSWFrZTFNeFR5Nzd0WVJ3MUNkVkJWWWFIbU8xM2k3ek8zYWVxdzloaGNHcWhyUQpXSWlYQ2lRdm9GN25oSmRvOEdmbkV5L1hKWk54LzQzbFVxUFcrekNhaWlsa2h3PT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUgUkVRVUVTVC0tLS0t")
	block, _ := pem.Decode([]byte(data))
	csr, _ := x509.ParseCertificateRequest(block.Bytes)

	a, err := srv.SignCertificate(ctx, caType, newCA.Name, *csr, false, csr.Subject.CommonName)
	data2, _ := base64.StdEncoding.DecodeString(a.Crt)
	block2, _ := pem.Decode([]byte(data2))
	crt, _ := x509.ParseCertificate(block2.Bytes)

	data3, _ := base64.StdEncoding.DecodeString("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ2pqQ0NBWFlDQVFBd1NURUxNQWtHQTFVRUJoTUNSVk14Q2pBSUJnTlZCQWdNQVVFeENqQUlCZ05WQkFjTQpBVUV4Q2pBSUJnTlZCQW9NQVVFeENqQUlCZ05WQkFzTUFVRXhDakFJQmdOVkJBTU1BVUV3Z2dFaU1BMEdDU3FHClNJYjNEUUVCQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUURDaFUxRFROckI0a2JTaVpjQjBMaHhUQ2dPYXlQUUU0VzkKT2N1MFBpczBybUliZnM2T2pERk5qcUY5dlhOcFlUSGhtL3FaTVZTWEZYZjM4VDBJS3NmU2lCYm5aa0pYWWc0NgptY2tLY1VkQ0VsUy8wK3RYaDh6Slo3QXNsV0Z2eXFLek5nUVJCcnhJQ0RVOTdVWXJ6eWk3ajVOSUJ2OHJvRld4CjVJOUNXUEpEQ00vRUFHMHVldjZQNVQzN2dKUzlFcnZXeERmWDVJL3hxRnZEQnpsV0VqbytFZ1piM3daSEt5d3QKMUVaVHBET1NKY29VeXZnWmFwUFF6U2JDZVdUL3ZlRW8rem5pUlk5SThFRlJhNm9DWDNCbVc4Snh2V2FSOVd3YQpnVUZ4cFM5OHdJN0JwSVJUeFgwdk9oMXZlUlBjWmRsVmFMZlJQb1BuV1BkdHAwckFDdXB6QWdNQkFBR2dBREFOCkJna3Foa2lHOXcwQkFRc0ZBQU9DQVFFQUllbTV5YnpVR1VvSk9yUjc1bW5COGZNUmVBWi9NalRVamYwem0xQjQKeGo4U1FMYTI2djU2ZkxOYkZ6NTlaaDlJa0J2U1AyNWNRTm5JU1lZT3RxejZLakJzcEVVQnNKaFVKcTNRNXpybgo3WVVoZnN2NWIzN0h2Y3h6akpvWW05NlZiU2FwQk5RWStGbjJ3R3NhZ1Zucktoalk0REdMM0lKQmlicmJvcEg2ClJwaFJRMWwyeXcwbUEybG9jK0hEZ1VwVTR4bXRpangvbHZmdHkzYVdwelBmV3pOWFRVYkEwNTFGY3hEQWh0SlkKbEd5WUxKSk1XQ08rL3NlUkxLSWFrZTFNeFR5Nzd0WVJ3MUNkVkJWWWFIbU8xM2k3ek8zYWVxdzloaGNHcWhyUQpXSWlYQ2lRdm9GN25oSmRvOEdmbkV5L1hKWk54LzQzbFVxUFcrekNhaWlsa2h3PT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUgUkVRVUVTVC0tLS0t")
	block3, _ := pem.Decode([]byte(data3))
	csr3, _ := x509.ParseCertificateRequest(block3.Bytes)

	b, err := srv.SignCertificate(ctx, caType, newCA.Name, *csr3, false, csr.Subject.CommonName)
	data4, _ := base64.StdEncoding.DecodeString(b.Crt)
	block4, _ := pem.Decode([]byte(data4))
	crt2, _ := x509.ParseCertificate(block4.Bytes)

	srv.DeleteCert(ctx, caType, newCA.Name, utils.InsertNth(utils.ToHexInt(crt2.SerialNumber), 2))

	testCases := []struct {
		name string
		cert *x509.Certificate
		ret  error
	}{
		{"Delete deleted CA", crt2, errors.New("the certificate is already revoked")},
		{"Delete certificate", crt, nil},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {
			num := utils.InsertNth(utils.ToHexInt(tc.cert.SerialNumber), 2)
			err = srv.DeleteCert(ctx, caType, newCA.Name, num)
			if err != nil {
				if tc.ret != err {
					if err.Error() != tc.ret.Error() {
						t.Errorf("Got result is %s; want %s", err, tc.ret)
					}
				}
			}

		})
	}
	if err != nil {
		t.Fatal("Could not delete certificate from file system")
	}
}

func setup(t *testing.T) (Service, context.Context) {
	t.Helper()

	logger := log.NewNopLogger()

	ctx := context.Background()
	_, ctx = opentracing.StartSpanFromContext(ctx, "test")
	ctx = context.WithValue(ctx, utils.LamassuLoggerContextKey, logger)

	level.Info(logger).Log("msg", "Jaeger tracer started")

	vaultClient, err := mocks.NewVaultSecretsMock(t)
	if err != nil {
		t.Fatal("Unable to create Vault in-memory client")
	}

	vaultSecret, err := vault.NewVaultSecretsWithClient(
		vaultClient,
		"",
		"pki/lamassu/dev/",
		"",
		"",
		"",
		"",
		"",
		logger,
	)
	if err != nil {
		t.Fatal("Unable to create Vault in-memory service")
	}

	casDb, _ := mocks.NewCasDBMock(t)

	srv := NewCAService(logger, vaultSecret, casDb)
	return srv, ctx
}

func testCA(caName string) dto.Cert {
	serialNumber := "54-91-80-de-65-98-1b-7f-7a-a4-08-4b-99-ae-8c-d8-8a-69-6b-8e"

	keyMetadata := dto.PrivateKeyMetadataWithStregth{
		KeyType: "rsa",
		KeyBits: 4096,
		//KeyStrength: "",
	}

	subject := dto.Subject{
		Country:          "ES",
		State:            "Gipuzkoa",
		Locality:         "Locality",
		Organization:     "Organization",
		OrganizationUnit: "OrganizationalUnit",
		CommonName:       "CommonName",
	}

	certContent := dto.CertContent{
		CerificateBase64: "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNURENDQWZPZ0F3SUJBZ0lVZnRXcTVObnpXZHUrSHk2S1RTMmpWazcybzRjd0NnWUlLb1pJemowRUF3SXcKY3pFTE1Ba0dBMVVFQmhNQ1JWTXhFVEFQQmdOVkJBZ1RDRWRwY0hWNmEyOWhNUkV3RHdZRFZRUUhFd2hCY25KaApjMkYwWlRFaE1BNEdBMVVFQ2hNSFV5NGdRMjl2Y0RBUEJnTlZCQW9UQ0V4TFV5Qk9aWGgwTVJzd0dRWURWUVFECkV4Sk1TMU1nVG1WNGRDQlNiMjkwSUVOQklETXdJQmNOTWpJd01USXdNVEV3TWpJMVdoZ1BNakExTWpBeE1UTXgKTVRBeU5UVmFNSE14Q3pBSkJnTlZCQVlUQWtWVE1SRXdEd1lEVlFRSUV3aEhhWEIxZW10dllURVJNQThHQTFVRQpCeE1JUVhKeVlYTmhkR1V4SVRBT0JnTlZCQW9UQjFNdUlFTnZiM0F3RHdZRFZRUUtFd2hNUzFNZ1RtVjRkREViCk1Ca0dBMVVFQXhNU1RFdFRJRTVsZUhRZ1VtOXZkQ0JEUVNBek1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMEQKQVFjRFFnQUU1aTFxZnlZU2xLaWt3SDhGZkhvQWxVWE44RlE3aE1OMERaTk8vVzdiSE44NVFpZ09ZeVQ1bWNYMgpXbDJtSTVEL0xQT1BKd0l4N1ZZcmxZU1BMTm5ndjZOak1HRXdEZ1lEVlIwUEFRSC9CQVFEQWdFR01BOEdBMVVkCkV3RUIvd1FGTUFNQkFmOHdIUVlEVlIwT0JCWUVGUGRURSs3a0k2MXFXSHFtUktZai9OaElIS01lTUI4R0ExVWQKSXdRWU1CYUFGUGRURSs3a0k2MXFXSHFtUktZai9OaElIS01lTUFvR0NDcUdTTTQ5QkFNQ0EwY0FNRVFDSUI2QQptZStjRzQ0MjBpNE5QZ1ZwWVRHN3hFN2lvbG0xOXhqRC9PcS9TeWt0QWlBaWRBK2JTanpvVHZxckRieDBqaHBiCmJpTnFycHZJY255TEY1MXQ5cHdBL1E9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0t",
		PublicKeyBase64:  "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFNWkxcWZ5WVNsS2lrd0g4RmZIb0FsVVhOOEZRNwpoTU4wRFpOTy9XN2JITjg1UWlnT1l5VDVtY1gyV2wybUk1RC9MUE9QSndJeDdWWXJsWVNQTE5uZ3Z3PT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==",
	}

	cert := dto.Cert{
		Status:       "issued",
		SerialNumber: serialNumber,
		Name:         caName,
		KeyMetadata:  keyMetadata,
		Subject:      subject,
		CertContent:  certContent,
		CaTTL:        2000,
		EnrollerTTL:  1000,
		ValidFrom:    "2022-01-31 15:00:08 +0000 UTC",
		ValidTo:      "2022-04-18 23:00:37 +0000 UTC",
	}
	return cert
}

func testCAImport() secrets.CAImport {
	return secrets.CAImport{
		PEMBundle: "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUY2RENDQTlDZ0F3SUJBZ0lVQlVGWEFEa3NVaWY2d0xpOHVCejNvZzBMeDNFd0RRWUpLb1pJaHZjTkFRRUwKQlFBd1ZURVBNQTBHQTFVRUJoTUdjM1J5YVc1bk1ROHdEUVlEVlFRSUV3WnpkSEpwYm1jeER6QU5CZ05WQkFjVApCbk4wY21sdVp6RVBNQTBHQTFVRUNoTUdjM1J5YVc1bk1ROHdEUVlEVlFRREV3WnpkSEpwYm1jd0hoY05Nakl3Ck1USXdNVFF4T0RNeFdoY05Nakl3TkRFek1qSXhPRFUzV2pCVk1ROHdEUVlEVlFRR0V3WnpkSEpwYm1jeER6QU4KQmdOVkJBZ1RCbk4wY21sdVp6RVBNQTBHQTFVRUJ4TUdjM1J5YVc1bk1ROHdEUVlEVlFRS0V3WnpkSEpwYm1jeApEekFOQmdOVkJBTVRCbk4wY21sdVp6Q0NBaUl3RFFZSktvWklodmNOQVFFQkJRQURnZ0lQQURDQ0Fnb0NnZ0lCCkFMTE1lWS82K0RuZTYrajlJQzMyZERWeXluajl0bFU4Q1RNUVZnNnhpMXp1N24zOUd0TEE1eXFvMnpMYUt4bkcKY3lQQVRyQldHeHBGOHBBYXQrMGo5QWRuSGREV09SOW1ab0J1bWpOWjVFRElXSFoyTWhmQWtUcnZGVkRjMUgxKwo4Qnp0TnpiYjdVNUJUblFCTUJqY2prUUNhUlNaTzAwanpRQjhoQVFWcVNQZTRESVFwVWdET2hTVTduOUo5NXk3CktmZHpFN2NHSCtwR2RtZTVXZytYSHBOM2Vra1A0bHZLWlgxSHV6cXQvb1VtckM5QzVzNERnSjhjQ0VYM0NrK1kKSUsxM3VQZ3d4cFZuY0JHTU1rUTBnc3AzckxJQ21rbTZPMXVRRmpwd1RWMm94UUNVbkltUUF4V1pxRjlvY0sxegpRNkdZcTdUWnVvaGxQT1M1bmNHRHArMlY1OTR6bTh5cUtEVHJWTVFPY095YTlnZS8zaHg3N08rN05pYkhDclFlCmt3U2diR04zZFIxaVV0TDZvdFlSemYwYVV2bjBWSDRUUWFOVTR1c3BadDlwMFl2OTRzcnRjbHdGMk5PWHFqT3UKdlRrVFpObjRaTDJWYkRoWDdkcHp3Z1FKNmd4aERiblV5aWxTaUtqOVZ5bEdFdWY1YUxyckEySFc3NFFVQWlZcgpqb0xkOE9mVWR1YkxkS3RRZXB5UXpyVzk3WTZnOXZWOE82M0o1TWc4cnhBNGJ0K3NId3JKbmFPVGhhV3A3dWFXClhrVFNYWk55QUJ6cmYwOU5USkNMOXh6TFh3cWUwd05tZXR6bitacE8vR2N6c3AybDdMaFBCQlVyL3EvZk0yRUUKZ1Q3WUNubGtnZ0lGcVFpOFVkdUlyUkJiOWorRW45aVExemNRbWJDN3V5eGpBZ01CQUFHamdhOHdnYXd3RGdZRApWUjBQQVFIL0JBUURBZ0VHTUE4R0ExVWRFd0VCL3dRRk1BTUJBZjh3SFFZRFZSME9CQllFRkZxc3hZd0hqSUVMCjR1TlZCV3JZb2dCcXJRR1VNQjhHQTFVZEl3UVlNQmFBRkZxc3hZd0hqSUVMNHVOVkJXcllvZ0JxclFHVU1EWUcKQ0NzR0FRVUZCd0VCQkNvd0tEQW1CZ2dyQmdFRkJRY3dBWVlhYUhSMGNEb3ZMMlJsZGk1c1lXMWhjM04xTG1sdgpPamt3T1Rnd0VRWURWUjBSQkFvd0NJSUdjM1J5YVc1bk1BMEdDU3FHU0liM0RRRUJDd1VBQTRJQ0FRQkptUTBMCmtaWTB5ajhTZXhnbEVyQTBpQW4vdlNyZVVIZE44anp5bGhzbDJ6WklIb0lQZ2ZjbnNrcktFQTZpdDlhUTJvNTEKMHA4YlhPOGtjb0xhMS93R1dSdm13TVBObHBmUDZRbjF1QkxGMnVHMkdyUEoyNGFUbUVOalRaaUxMRElxR3VUcwpPa1UvMU84eS9DdFJBWmlVR0RFM1RPRGN1eWlBNXAzYVVwc1VBZzA0cFdCWkFIN1p5cTdxMXNjYXdQczNpUFpaCkNVVmFRL3Z0Wmt6ckMzRFlJeDFFUmNHLzJLK3dTT0lIZTdYUlVZNi9jNkdjUXRwS2J2T2ZqR3QvcS9xWUJzSkUKRXRBS1hYbHJRSWJHYmVZdm9ZcWVwTUROV3VHQjBRZi8zcnVHZk93YU4vYUtZbW1icEtON0RYN3dDcVNTYkd2SApHdE5mNlZQVnJMSm8zZjFsSVg1bnBXRGQzNFF5TVpSNUNnbHdES2tKaGNmT0J3c1RBRTRMcEVRU0ZPTEx6QUI4CnNTTzg4b1BBTlR0UGhyMi9URk9DTlZIQVRJckNML3B6RUxmWDJmL2llSURtaXZ2WTB6UlJtZUVQbSt0bXhadnEKR21ZVlg0VVRDWTVQazVyUHRJZE1qNk5wcFNVaVo1WjkrTjBPUlBWSjhhdmV1UGVCcTdsUmVUNnlNUTFkREU4MwovRTZ4MThLMHR0dThMUVdVcXFHazZlVEVaMHdLMjhxMW03TmxuMDBCb1FGU2FNWnBKUXlEakp3dVVwQXhtTm0yCkdDZnI4azRBQ01VaUFaSG56M2RnY3RGTXJ2aVVIQ1QrMWxSOVJTenZ0Nk1IdjhuUVArM0YybzkzUUpMQnd0VXcKZTRKdGFFYWxadlV0LzFKZzVkd0Q4aytvcFQxRTZiQ3liOE8xZHc9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0t",
		TTL:       1000,
	}
}

func _generateCSR(ctx context.Context, keyType string, priv interface{}, commonName string, country string, state string, locality string, org string, orgUnit string) ([]byte, error) {
	var signingAlgorithm x509.SignatureAlgorithm
	if keyType == "EC" {
		signingAlgorithm = x509.ECDSAWithSHA256
	} else {
		signingAlgorithm = x509.SHA256WithRSA

	}
	//emailAddress := csrForm.EmailAddress
	subj := pkix.Name{
		CommonName:         commonName,
		Country:            []string{country},
		Province:           []string{state},
		Locality:           []string{locality},
		Organization:       []string{org},
		OrganizationalUnit: []string{orgUnit},
	}
	rawSubj := subj.ToRDNSequence()
	/*rawSubj = append(rawSubj, []pkix.AttributeTypeAndValue{
		{Type: oidEmailAddress, Value: emailAddress},
	})*/
	asn1Subj, _ := asn1.Marshal(rawSubj)
	template := x509.CertificateRequest{
		RawSubject: asn1Subj,
		//EmailAddresses:     []string{emailAddress},
		SignatureAlgorithm: signingAlgorithm,
	}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, priv)
	return csrBytes, err
}
func getKeyStrength(keyType string, keyBits int) string {
	var keyStrength string = "unknown"
	switch keyType {
	case "RSA":
		if keyBits < 2048 {
			keyStrength = "low"
		} else if keyBits >= 2048 && keyBits < 3072 {
			keyStrength = "medium"
		} else {
			keyStrength = "high"
		}
	case "EC":
		if keyBits < 224 {
			keyStrength = "low"
		} else if keyBits >= 224 && keyBits < 256 {
			keyStrength = "medium"
		} else {
			keyStrength = "high"
		}
	}
	return keyStrength
}
