package models

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strings"
)

type KeyUsage x509.KeyUsage

func (p KeyUsage) MarshalText() ([]byte, error) {
	usages := []string{}
	if p&KeyUsage(x509.KeyUsageDigitalSignature) != 0 {
		usages = append(usages, "DigitalSignature")
	}

	if p&KeyUsage(x509.KeyUsageContentCommitment) != 0 {
		usages = append(usages, "ContentCommitment")
	}

	if p&KeyUsage(x509.KeyUsageKeyEncipherment) != 0 {
		usages = append(usages, "KeyEncipherment")
	}

	if p&KeyUsage(x509.KeyUsageDataEncipherment) != 0 {
		usages = append(usages, "DataEncipherment")
	}

	if p&KeyUsage(x509.KeyUsageKeyAgreement) != 0 {
		usages = append(usages, "KeyAgreement")
	}

	if p&KeyUsage(x509.KeyUsageCertSign) != 0 {
		usages = append(usages, "CertSign")
	}

	if p&KeyUsage(x509.KeyUsageCRLSign) != 0 {
		usages = append(usages, "CRLSign")
	}

	if p&KeyUsage(x509.KeyUsageEncipherOnly) != 0 {
		usages = append(usages, "EncipherOnly")
	}

	if p&KeyUsage(x509.KeyUsageDecipherOnly) != 0 {
		usages = append(usages, "DecipherOnly")
	}

	return json.Marshal(usages)
}

func (c *KeyUsage) UnmarshalJSON(data []byte) error {
	var usages x509.KeyUsage

	usagesStr := []string{}

	var singleUsage string
	err := json.Unmarshal(data, &singleUsage)
	if err != nil {
		var usageArr []string
		err = json.Unmarshal(data, &usageArr)
		if err != nil {
			return fmt.Errorf("invalid format")
		}

		usagesStr = usageArr
	} else {
		usagesStr = append(usagesStr, singleUsage)
	}

	for _, part := range usagesStr {
		trimmedPart := strings.TrimSpace(part)

		switch trimmedPart {
		case "DigitalSignature":
			usages |= x509.KeyUsageDigitalSignature
		case "ContentCommitment":
			usages |= x509.KeyUsageContentCommitment
		case "KeyEncipherment":
			usages |= x509.KeyUsageKeyEncipherment
		case "DataEncipherment":
			usages |= x509.KeyUsageDataEncipherment
		case "KeyAgreement":
			usages |= x509.KeyUsageKeyAgreement
		case "CertSign":
			usages |= x509.KeyUsageCertSign
		case "CRLSign":
			usages |= x509.KeyUsageCRLSign
		case "EncipherOnly":
			usages |= x509.KeyUsageEncipherOnly
		case "DecipherOnly":
			usages |= x509.KeyUsageDecipherOnly
		default:
			return fmt.Errorf("unknown key usage: %s", trimmedPart)
		}
	}

	return nil
}

type ExtendedKeyUsage x509.ExtKeyUsage

func (p ExtendedKeyUsage) MarshalText() ([]byte, error) {
	str := ""
	switch p {
	case ExtendedKeyUsage(x509.ExtKeyUsageAny):
		str = "Any"
	case ExtendedKeyUsage(x509.ExtKeyUsageServerAuth):
		str = "ServerAuth"
	case ExtendedKeyUsage(x509.ExtKeyUsageClientAuth):
		str = "ClientAuth"
	case ExtendedKeyUsage(x509.ExtKeyUsageCodeSigning):
		str = "CodeSigning"
	case ExtendedKeyUsage(x509.ExtKeyUsageEmailProtection):
		str = "EmailProtection"
	case ExtendedKeyUsage(x509.ExtKeyUsageIPSECEndSystem):
		str = "IPSECEndSystem"
	case ExtendedKeyUsage(x509.ExtKeyUsageIPSECTunnel):
		str = "IPSECTunnel"
	case ExtendedKeyUsage(x509.ExtKeyUsageIPSECUser):
		str = "IPSECUser"
	case ExtendedKeyUsage(x509.ExtKeyUsageTimeStamping):
		str = "TimeStamping"
	case ExtendedKeyUsage(x509.ExtKeyUsageOCSPSigning):
		str = "OCSPSigning"
	}

	return json.Marshal(str)
}

func (c *ExtendedKeyUsage) UnmarshalJSON(data []byte) error {
	var usage ExtendedKeyUsage

	var singleUsage string
	err := json.Unmarshal(data, &singleUsage)
	if err != nil {
		if err != nil {
			return fmt.Errorf("invalid format")
		}

	}

	switch singleUsage {
	case "Any":
		usage = ExtendedKeyUsage(x509.ExtKeyUsageAny)
	case "ServerAuth":
		usage = ExtendedKeyUsage(x509.ExtKeyUsageServerAuth)
	case "ClientAuth":
		usage = ExtendedKeyUsage(x509.ExtKeyUsageClientAuth)
	case "CodeSigning":
		usage = ExtendedKeyUsage(x509.ExtKeyUsageCodeSigning)
	case "EmailProtection":
		usage = ExtendedKeyUsage(x509.ExtKeyUsageEmailProtection)
	case "IPSECEndSystem":
		usage = ExtendedKeyUsage(x509.ExtKeyUsageIPSECEndSystem)
	case "IPSECTunnel":
		usage = ExtendedKeyUsage(x509.ExtKeyUsageIPSECTunnel)
	case "IPSECUser":
		usage = ExtendedKeyUsage(x509.ExtKeyUsageIPSECUser)
	case "TimeStamping":
		usage = ExtendedKeyUsage(x509.ExtKeyUsageTimeStamping)
	case "OCSPSigning":
		usage = ExtendedKeyUsage(x509.ExtKeyUsageOCSPSigning)
	default:
		return fmt.Errorf("unknown extended key usage: %s", singleUsage)
	}

	c = &usage

	return nil
}
