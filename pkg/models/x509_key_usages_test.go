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
		keyUsage       KeyUsage
		expectedString string
	}{
		{
			name:           "OK/Usage1",
			keyUsage:       KeyUsage(x509.KeyUsageDigitalSignature),
			expectedString: `["DigitalSignature"]`,
		},
		{
			name:           "OK/Usage256",
			keyUsage:       KeyUsage(x509.KeyUsageDecipherOnly),
			expectedString: `["DecipherOnly"]`,
		},
		{
			name:           "OK/UsageNoneOrInvalid",
			keyUsage:       KeyUsage(0),
			expectedString: `[]`,
		},
		{
			name: "OK/AllUsages",
			keyUsage: KeyUsage(x509.KeyUsageDigitalSignature |
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

func TestKeyUsageUnmarshal(t *testing.T) {
	var testcases = []struct {
		name             string
		keyUsage         string
		expectedKeyUsage KeyUsage
		expectedErr      error
	}{
		{
			name:             "OK/Usage1",
			keyUsage:         `["DigitalSignature"]`,
			expectedKeyUsage: KeyUsage(x509.KeyUsageDigitalSignature),
			expectedErr:      nil,
		},
		{
			name:             "OK/Usage256",
			keyUsage:         `["DecipherOnly"]`,
			expectedKeyUsage: KeyUsage(x509.KeyUsageDigitalSignature),
			expectedErr:      nil,
		},
		{
			name:     "OK/AllUsages",
			keyUsage: `["DigitalSignature","ContentCommitment","KeyEncipherment","DataEncipherment","KeyAgreement","CertSign","CRLSign","EncipherOnly","DecipherOnly"]`,
			expectedKeyUsage: KeyUsage(x509.KeyUsageDigitalSignature |
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
			name:             "OK/Usage256",
			keyUsage:         `"KeyEncipherment"`,
			expectedKeyUsage: KeyUsage(x509.KeyUsageEncipherOnly),
			expectedErr:      nil,
		},
		{
			name:             "Err/Usage256",
			keyUsage:         `aaa`,
			expectedKeyUsage: KeyUsage(0),
			expectedErr:      fmt.Errorf("invalid format"),
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {

			var keyUsage KeyUsage
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
		keyUsage       ExtendedKeyUsage
		expectedString string
	}{
		{
			name:           "OK/Any",
			keyUsage:       ExtendedKeyUsage(x509.ExtKeyUsageAny),
			expectedString: `"Any"`,
		},
		{
			name:           "OK/ServerAuth",
			keyUsage:       ExtendedKeyUsage(x509.ExtKeyUsageServerAuth),
			expectedString: `"ServerAuth"`,
		},
		{
			name:           "OK/ClientAuth",
			keyUsage:       ExtendedKeyUsage(x509.ExtKeyUsageClientAuth),
			expectedString: `"ClientAuth"`,
		},
		{
			name:           "OK/CodeSigning",
			keyUsage:       ExtendedKeyUsage(x509.ExtKeyUsageCodeSigning),
			expectedString: `"CodeSigning"`,
		},
		{
			name:           "OK/EmailProtection",
			keyUsage:       ExtendedKeyUsage(x509.ExtKeyUsageEmailProtection),
			expectedString: `"EmailProtection"`,
		},
		{
			name:           "OK/IPSECEndSystem",
			keyUsage:       ExtendedKeyUsage(x509.ExtKeyUsageIPSECEndSystem),
			expectedString: `"IPSECEndSystem"`,
		},
		{
			name:           "OK/IPSECTunnel",
			keyUsage:       ExtendedKeyUsage(x509.ExtKeyUsageIPSECTunnel),
			expectedString: `"IPSECTunnel"`,
		},
		{
			name:           "OK/IPSECUser",
			keyUsage:       ExtendedKeyUsage(x509.ExtKeyUsageIPSECUser),
			expectedString: `"IPSECUser"`,
		},
		{
			name:           "OK/OCSPSigning",
			keyUsage:       ExtendedKeyUsage(x509.ExtKeyUsageOCSPSigning),
			expectedString: `"OCSPSigning"`,
		},
		{
			name:           "OK/TimeStamping",
			keyUsage:       ExtendedKeyUsage(x509.ExtKeyUsageTimeStamping),
			expectedString: `"TimeStamping"`,
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
		expectedKeyUsage ExtendedKeyUsage
		expectedErr      error
	}{
		{
			name:             "OK/Any",
			keyUsage:         `"Any"`,
			expectedKeyUsage: ExtendedKeyUsage(x509.ExtKeyUsageAny),
			expectedErr:      nil,
		},
		{
			name:             "OK/ServerAuth",
			keyUsage:         `"ServerAuth"`,
			expectedKeyUsage: ExtendedKeyUsage(x509.ExtKeyUsageServerAuth),
			expectedErr:      nil,
		},
		{
			name:             "OK/ClientAuth",
			keyUsage:         `"ClientAuth"`,
			expectedKeyUsage: ExtendedKeyUsage(x509.ExtKeyUsageClientAuth),
			expectedErr:      nil,
		},
		{
			name:             "OK/CodeSigning",
			keyUsage:         `"CodeSigning"`,
			expectedKeyUsage: ExtendedKeyUsage(x509.ExtKeyUsageClientAuth),
			expectedErr:      nil,
		},
		{
			name:             "OK/EmailProtection",
			keyUsage:         `"EmailProtection"`,
			expectedKeyUsage: ExtendedKeyUsage(x509.ExtKeyUsageEmailProtection),
			expectedErr:      nil,
		},
		{
			name:             "OK/IPSECEndSystem",
			keyUsage:         `"IPSECEndSystem"`,
			expectedKeyUsage: ExtendedKeyUsage(x509.ExtKeyUsageIPSECEndSystem),
			expectedErr:      nil,
		},
		{
			name:             "OK/IPSECTunnel",
			keyUsage:         `"IPSECTunnel"`,
			expectedKeyUsage: ExtendedKeyUsage(x509.ExtKeyUsageIPSECTunnel),
			expectedErr:      nil,
		},
		{
			name:             "OK/IPSECUser",
			keyUsage:         `"IPSECUser"`,
			expectedKeyUsage: ExtendedKeyUsage(x509.ExtKeyUsageIPSECUser),
			expectedErr:      nil,
		},
		{
			name:             "OK/OCSPSigning",
			keyUsage:         `"OCSPSigning"`,
			expectedKeyUsage: ExtendedKeyUsage(x509.ExtKeyUsageOCSPSigning),
			expectedErr:      nil,
		},
		{
			name:             "OK/TimeStamping",
			keyUsage:         `"TimeStamping"`,
			expectedKeyUsage: ExtendedKeyUsage(x509.ExtKeyUsageTimeStamping),
			expectedErr:      nil,
		},
		{
			name:             "Err/InvalidFormat",
			keyUsage:         "aaa",
			expectedKeyUsage: ExtendedKeyUsage(0),
			expectedErr:      fmt.Errorf("invalid format"),
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {

			var keyUsage ExtendedKeyUsage
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
