package models

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"reflect"
	"testing"
)

func TestX509CertificateMarshalJSON(t *testing.T) {
	cert := &X509Certificate{
		Raw: []byte("certificate data"),
	}

	expected := []byte("\"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tClkyVnlkR2xtYVdOaGRHVWdaR0YwWVE9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==\"")

	data, err := cert.MarshalJSON()
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	if string(data) != string(expected) {
		t.Fatalf("unexpected data: got %s, want %s", data, expected)
	}
}

func TestX509CertificateMarshalJSONNilCertificate(t *testing.T) {
	var cert *X509Certificate

	expected := []byte("\"\"")

	data, err := cert.MarshalJSON()
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	if !reflect.DeepEqual(data, expected) {
		t.Fatalf("unexpected data: got %s, want %s", data, expected)
	}
}

func TestX509CertificateUnmarshal(t *testing.T) {
	pemCert, err := os.ReadFile("../helpers/testdata/cacertificate.pem")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	certDERBlock, _ := pem.Decode(pemCert)
	cert, err := x509.ParseCertificate(certDERBlock.Bytes)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	expected := X509Certificate(*cert)

	marshaled, err := expected.MarshalJSON()
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	var result X509Certificate
	err = result.UnmarshalJSON(marshaled)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	if !reflect.DeepEqual(result, expected) {
		t.Fatalf("unexpected data: got %v, want %v", result, expected)
	}

}
func TestX509CertificateRequestMarshalJSON(t *testing.T) {
	certReq := &X509CertificateRequest{
		Raw: []byte("certificate request data"),
	}

	expected := []byte("\"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KWTJWeWRHbG1hV05oZEdVZ2NtVnhkV1Z6ZENCa1lYUmgKLS0tLS1FTkQgQ0VSVElGSUNBVEUgUkVRVUVTVC0tLS0tCg==\"")

	data, err := certReq.MarshalJSON()
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	if string(data) != string(expected) {
		t.Fatalf("unexpected data: got %s, want %s", data, expected)
	}
}

func TestX509CertificateRequestMarshalJSONNilCertificateRequest(t *testing.T) {
	var certReq *X509CertificateRequest

	expected := []byte("\"\"")

	data, err := certReq.MarshalJSON()
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	if !reflect.DeepEqual(data, expected) {
		t.Fatalf("unexpected data: got %s, want %s", data, expected)
	}
}
func TestX509CertificateRequestUnmarshalJSON(t *testing.T) {
	csr, err := os.ReadFile("../helpers/testdata/samplecsr.pem")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	csrDERBlock, _ := pem.Decode(csr)

	parsedCertReq, err := x509.ParseCertificateRequest(csrDERBlock.Bytes)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	certReq := X509CertificateRequest(*parsedCertReq)
	mashaledCertReq, err := certReq.MarshalJSON()
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	data := []byte("\"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ1V6Q0NBVDBDQVFBd0VERU9NQXdHQTFVRUF4TUZaSFZ0Ylhrd2dnRWlNQTBHQ1NxR1NJYjNEUUVCQVFVQQpBNElCRHdBd2dnRUtBb0lCQVFDbEtDcUptWDJmUEY4NDljNzI5R3FGa1Nsa29vTFY1bkFmUVFXWVJXRzBBS3czCmQ5RXlDSjlaNi9Yd0dUR09ZMjdsRjZiR0ZxTldEMlk3ejg5UFJoVm1MNmh5SU5YZzgzRDhjRVpYZzJtSVd6TGQKV0EyQzJnNzFzMDlhZFE2SDJEcGRZODNzYk9kL21Jc0JMK3BQSXJUd2VPTGFPQWFQenN3c3gxRUJwUXk1d2hqegpyVTAzdGhEVmV2dWJOZGl2cDFmSGFGa1VheHQ5Um1PcTJTQU1xbDQzWFRVUjVhamM1SmRxMzRucVg0dHlEVG16Cmc1V1phYlJtLzFYNDNVeE5aS1hyaGN1WFdYZkFoM2ZvWXhaU2ZmVWFxNnJPQ0FjQXpCWloyUnN1eHlrVUtaK3MKZkJLMVd2RG94MkhyTy9jQTZUTlZ1V0RVcUs3K1NPajZKaDk2S3g4eEFnTUJBQUdnQURBTEJna3Foa2lHOXcwQgpBUXNEZ2dFQkFJTGxwM3plS0EvVWxDVkp1YnRpRXRxOExiNWxMRkV0UG9jekl5dDJjYjBwZnpnU2VUbVVNbzc3CmhDRWtQRWlWWVRYUEp6Nk9vSWFTVVZRUk9iek11NHVYNlZ6dGFRTDBuM1g0Z3hKMm4va3kyT2UzbUtheG1HTlMKSldCN2J0ZFhKT1JQMXhlZlREazAxUzBLWDZJMitjd2NSaWVvL1pobGxEWG1YU0QxRDVQbU5wSHRGcy9DdXNKegpNQXVMVVRqUGVUUjF3K0l4ampJVHZkc2ZoRXA0SCtSWkgyMFJ2R2pNc05zQldYZkN6OFVWWEFZMjJtTkJ3YWF3CjdheVVMRUJQa3FZVjZkK1lDV1QzNWtYWWtlVGtjbFI5aUszczRXaG94UFpCT3NVODFBbERRSnBIUEIyR3IrKzIKNjNHRjU3VndJejB0RzlFWHFQMThIdTZ0MTh2b2doOD0KLS0tLS1FTkQgQ0VSVElGSUNBVEUgUkVRVUVTVC0tLS0tCg==\"")
	if string(data) != string(mashaledCertReq) {
		t.Fatalf("unexpected data: got %s, want %s", mashaledCertReq, data)
	}

	var certReqUnmarshal X509CertificateRequest
	err = certReqUnmarshal.UnmarshalJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	if !reflect.DeepEqual(certReqUnmarshal, X509CertificateRequest(*parsedCertReq)) {
		t.Fatalf("unexpected data: got %v, want %v", certReq, X509CertificateRequest(*parsedCertReq))
	}
}

func TestX509CertificateRequestUnmarshalJSONMissingCertBlock(t *testing.T) {
	data := []byte("\"\"")

	var certReq X509CertificateRequest
	err := certReq.UnmarshalJSON(data)
	if err == nil {
		t.Fatal("expected error, but got nil")
	}

	expectedErr := fmt.Errorf("missing cert block")
	if err.Error() != expectedErr.Error() {
		t.Fatalf("unexpected error: got %s, want %s", err, expectedErr)
	}
}
