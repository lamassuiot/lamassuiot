package helpers

import (
	"crypto/x509"
	"testing"
)

func TestX509CertFingerprint(t *testing.T) {
	cert1 := x509.Certificate{}
	expected1 := "DA:39:A3:EE:5E:6B:4B:0D:32:55:BF:EF:95:60:18:90:AF:D8:07:09"
	result1 := X509CertFingerprint(cert1)
	if result1 != expected1 {
		t.Errorf("Expected %v, but got %v", expected1, result1)
	}

	cert2 := x509.Certificate{
		Raw: []byte{0x01, 0x02, 0x03, 0x04},
	}
	expected2 := "12:DA:DA:1F:FF:4D:47:87:AD:E3:33:31:47:20:2C:3B:44:3E:37:6F"
	result2 := X509CertFingerprint(cert2)
	if result2 != expected2 {
		t.Errorf("Expected %v, but got %v", expected2, result2)
	}

	cert3 := x509.Certificate{
		Raw: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
	}
	expected3 := "DD:57:83:BC:F1:E9:00:2B:C0:0A:D5:B8:3A:95:ED:6E:4E:BB:4A:D5"
	result3 := X509CertFingerprint(cert3)
	if result3 != expected3 {
		t.Errorf("Expected %v, but got %v", expected3, result3)
	}
}
