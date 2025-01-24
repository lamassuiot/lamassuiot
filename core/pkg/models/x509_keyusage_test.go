package models

import (
	"crypto/x509"
	"fmt"
	"strings"
	"testing"
)

func TestKeyUsageMarshal(t *testing.T) {
	var testcases = []struct {
		name           string
		keyUsage       X509KeyUsage
		expectedString string
	}{
		{
			name:           "OK/Usage1",
			keyUsage:       X509KeyUsage(x509.KeyUsageDigitalSignature),
			expectedString: `["DigitalSignature"]`,
		},
		{
			name:           "OK/Usage256",
			keyUsage:       X509KeyUsage(x509.KeyUsageDecipherOnly),
			expectedString: `["DecipherOnly"]`,
		},
		{
			name:           "OK/UsageNoneOrInvalid",
			keyUsage:       X509KeyUsage(0),
			expectedString: `[]`,
		},
		{
			name: "OK/AllUsages",
			keyUsage: X509KeyUsage(x509.KeyUsageDigitalSignature |
				x509.KeyUsageContentCommitment |
				x509.KeyUsageKeyEncipherment |
				x509.KeyUsageDataEncipherment |
				x509.KeyUsageKeyAgreement |
				x509.KeyUsageCertSign |
				x509.KeyUsageCRLSign |
				x509.KeyUsageEncipherOnly |
				x509.KeyUsageDecipherOnly,
			),
			expectedString: `["DigitalSignature","ContentCommitment","KeyEncipherment","DataEncipherment","KeyAgreement","CertSign","CRLSign","EncipherOnly","DecipherOnly"]`,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			keyUsageB, err := tc.keyUsage.MarshalJSON()
			if err != nil {
				t.Fatalf("got error while marshaling key usage: %s", err)
			}

			if string(keyUsageB) != tc.expectedString {
				t.Fatalf("unexpected string. Expected '%s'. Got '%s'", tc.expectedString, string(keyUsageB))
			}
		})
	}
}

func TestKeyUsageUnmarshal(t *testing.T) {
	var testcases = []struct {
		name             string
		keyUsage         string
		expectedKeyUsage X509KeyUsage
		expectedErr      error
	}{
		{
			name:             "OK/Usage1",
			keyUsage:         `["DigitalSignature"]`,
			expectedKeyUsage: X509KeyUsage(x509.KeyUsageDigitalSignature),
			expectedErr:      nil,
		},
		{
			name:             "OK/Usage256",
			keyUsage:         `["DecipherOnly"]`,
			expectedKeyUsage: X509KeyUsage(x509.KeyUsageDigitalSignature),
			expectedErr:      nil,
		},
		{
			name:     "OK/AllUsages",
			keyUsage: `["DigitalSignature","ContentCommitment","KeyEncipherment","DataEncipherment","KeyAgreement","CertSign","CRLSign","EncipherOnly","DecipherOnly"]`,
			expectedKeyUsage: X509KeyUsage(x509.KeyUsageDigitalSignature |
				x509.KeyUsageContentCommitment |
				x509.KeyUsageKeyEncipherment |
				x509.KeyUsageDataEncipherment |
				x509.KeyUsageKeyAgreement |
				x509.KeyUsageCertSign |
				x509.KeyUsageCRLSign |
				x509.KeyUsageEncipherOnly |
				x509.KeyUsageDecipherOnly,
			),
			expectedErr: nil,
		},
		{
			name:     "OK/2Usages",
			keyUsage: `["ContentCommitment","KeyAgreement","CertSign"]`,
			expectedKeyUsage: X509KeyUsage(x509.KeyUsageContentCommitment |
				x509.KeyUsageKeyAgreement |
				x509.KeyUsageCertSign,
			),
			expectedErr: nil,
		},
		{
			name:             "OK/Usage256",
			keyUsage:         `"KeyEncipherment"`,
			expectedKeyUsage: X509KeyUsage(x509.KeyUsageEncipherOnly),
			expectedErr:      nil,
		},
		{
			name:             "Err/Usage256",
			keyUsage:         `aaa`,
			expectedKeyUsage: X509KeyUsage(0),
			expectedErr:      fmt.Errorf("invalid format"),
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {

			var keyUsage X509KeyUsage
			err := keyUsage.UnmarshalJSON([]byte(tc.keyUsage))
			if err != nil {
				if tc.expectedErr != nil {
					if !strings.Contains(err.Error(), tc.expectedErr.Error()) {
						t.Fatalf("got unexpected while unmarshaling key usage. Expected %s. Got %s", tc.expectedErr, err)
					}
				} else {
					t.Fatalf("got unexpected while unmarshaling key usage. Got %s", err)
				}
			} else {
				if tc.expectedErr != nil {
					t.Fatalf("expected error %s but got none", err)
				}
			}
		})
	}

}
func TestExtendedKeyUsageMarshal(t *testing.T) {
	var testcases = []struct {
		name           string
		keyUsage       X509ExtKeyUsage
		expectedString string
	}{
		{
			name:           "OK/Any",
			keyUsage:       X509ExtKeyUsage(x509.ExtKeyUsageAny),
			expectedString: "Any",
		},
		{
			name:           "OK/ServerAuth",
			keyUsage:       X509ExtKeyUsage(x509.ExtKeyUsageServerAuth),
			expectedString: "ServerAuth",
		},
		{
			name:           "OK/ClientAuth",
			keyUsage:       X509ExtKeyUsage(x509.ExtKeyUsageClientAuth),
			expectedString: "ClientAuth",
		},
		{
			name:           "OK/CodeSigning",
			keyUsage:       X509ExtKeyUsage(x509.ExtKeyUsageCodeSigning),
			expectedString: "CodeSigning",
		},
		{
			name:           "OK/EmailProtection",
			keyUsage:       X509ExtKeyUsage(x509.ExtKeyUsageEmailProtection),
			expectedString: "EmailProtection",
		},
		{
			name:           "OK/IPSECEndSystem",
			keyUsage:       X509ExtKeyUsage(x509.ExtKeyUsageIPSECEndSystem),
			expectedString: "IPSECEndSystem",
		},
		{
			name:           "OK/IPSECTunnel",
			keyUsage:       X509ExtKeyUsage(x509.ExtKeyUsageIPSECTunnel),
			expectedString: "IPSECTunnel",
		},
		{
			name:           "OK/IPSECUser",
			keyUsage:       X509ExtKeyUsage(x509.ExtKeyUsageIPSECUser),
			expectedString: "IPSECUser",
		},
		{
			name:           "OK/OCSPSigning",
			keyUsage:       X509ExtKeyUsage(x509.ExtKeyUsageOCSPSigning),
			expectedString: "OCSPSigning",
		},
		{
			name:           "OK/TimeStamping",
			keyUsage:       X509ExtKeyUsage(x509.ExtKeyUsageTimeStamping),
			expectedString: "TimeStamping",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			keyUsageB, err := tc.keyUsage.MarshalText()
			if err != nil {
				t.Fatalf("got error while marshaling key usage: %s", err)
			}

			if string(keyUsageB) != tc.expectedString {
				t.Fatalf("unexpected string. Expected '%s'. Got '%s'", tc.expectedString, string(keyUsageB))
			}
		})
	}
}

func TestExtendedKeyUsageUnmarshal(t *testing.T) {
	var testcases = []struct {
		name             string
		keyUsage         string
		expectedKeyUsage X509ExtKeyUsage
		expectedErr      error
	}{
		{
			name:             "OK/Any",
			keyUsage:         "Any",
			expectedKeyUsage: X509ExtKeyUsage(x509.ExtKeyUsageAny),
			expectedErr:      nil,
		},
		{
			name:             "OK/ServerAuth",
			keyUsage:         "ServerAuth",
			expectedKeyUsage: X509ExtKeyUsage(x509.ExtKeyUsageServerAuth),
			expectedErr:      nil,
		},
		{
			name:             "OK/ClientAuth",
			keyUsage:         "ClientAuth",
			expectedKeyUsage: X509ExtKeyUsage(x509.ExtKeyUsageClientAuth),
			expectedErr:      nil,
		},
		{
			name:             "OK/CodeSigning",
			keyUsage:         "CodeSigning",
			expectedKeyUsage: X509ExtKeyUsage(x509.ExtKeyUsageClientAuth),
			expectedErr:      nil,
		},
		{
			name:             "OK/EmailProtection",
			keyUsage:         "EmailProtection",
			expectedKeyUsage: X509ExtKeyUsage(x509.ExtKeyUsageEmailProtection),
			expectedErr:      nil,
		},
		{
			name:             "OK/IPSECEndSystem",
			keyUsage:         "IPSECEndSystem",
			expectedKeyUsage: X509ExtKeyUsage(x509.ExtKeyUsageIPSECEndSystem),
			expectedErr:      nil,
		},
		{
			name:             "OK/IPSECTunnel",
			keyUsage:         "IPSECTunnel",
			expectedKeyUsage: X509ExtKeyUsage(x509.ExtKeyUsageIPSECTunnel),
			expectedErr:      nil,
		},
		{
			name:             "OK/IPSECUser",
			keyUsage:         "IPSECUser",
			expectedKeyUsage: X509ExtKeyUsage(x509.ExtKeyUsageIPSECUser),
			expectedErr:      nil,
		},
		{
			name:             "OK/OCSPSigning",
			keyUsage:         "OCSPSigning",
			expectedKeyUsage: X509ExtKeyUsage(x509.ExtKeyUsageOCSPSigning),
			expectedErr:      nil,
		},
		{
			name:             "OK/TimeStamping",
			keyUsage:         "TimeStamping",
			expectedKeyUsage: X509ExtKeyUsage(x509.ExtKeyUsageTimeStamping),
			expectedErr:      nil,
		},
		{
			name:             "Err/InvalidFormat",
			keyUsage:         "aaa",
			expectedKeyUsage: X509ExtKeyUsage(0),
			expectedErr:      fmt.Errorf("unsupported ext key usage"),
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {

			var keyUsage X509ExtKeyUsage
			err := keyUsage.UnmarshalText([]byte(tc.keyUsage))
			if err != nil {
				if tc.expectedErr != nil {
					if !strings.Contains(err.Error(), tc.expectedErr.Error()) {
						t.Fatalf("got unexpected while unmarshaling key usage. Expected %s. Got %s", tc.expectedErr, err)
					}
				} else {
					t.Fatalf("got unexpected while unmarshaling key usage. Got %s", err)
				}
			} else {
				if tc.expectedErr != nil {
					t.Fatalf("expected error %s but got none", err)
				}
			}
		})
	}

}
