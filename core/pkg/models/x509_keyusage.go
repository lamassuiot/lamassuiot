package models

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strings"
)

type X509KeyUsage x509.KeyUsage

func (p X509KeyUsage) MarshalText() ([]byte, error) {
	usages := []string{}
	if p&X509KeyUsage(x509.KeyUsageDigitalSignature) != 0 {
		usages = append(usages, "DigitalSignature")
	}

	if p&X509KeyUsage(x509.KeyUsageContentCommitment) != 0 {
		usages = append(usages, "ContentCommitment")
	}

	if p&X509KeyUsage(x509.KeyUsageKeyEncipherment) != 0 {
		usages = append(usages, "KeyEncipherment")
	}

	if p&X509KeyUsage(x509.KeyUsageDataEncipherment) != 0 {
		usages = append(usages, "DataEncipherment")
	}

	if p&X509KeyUsage(x509.KeyUsageKeyAgreement) != 0 {
		usages = append(usages, "KeyAgreement")
	}

	if p&X509KeyUsage(x509.KeyUsageCertSign) != 0 {
		usages = append(usages, "CertSign")
	}

	if p&X509KeyUsage(x509.KeyUsageCRLSign) != 0 {
		usages = append(usages, "CRLSign")
	}

	if p&X509KeyUsage(x509.KeyUsageEncipherOnly) != 0 {
		usages = append(usages, "EncipherOnly")
	}

	if p&X509KeyUsage(x509.KeyUsageDecipherOnly) != 0 {
		usages = append(usages, "DecipherOnly")
	}

	return json.Marshal(usages)
}

func (c *X509KeyUsage) UnmarshalJSON(data []byte) error {
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

type X509ExtKeyUsage x509.ExtKeyUsage

func (p X509ExtKeyUsage) MarshalText() ([]byte, error) {
	str := ""
	switch p {
	case X509ExtKeyUsage(x509.ExtKeyUsageAny):
		str = "Any"
	case X509ExtKeyUsage(x509.ExtKeyUsageServerAuth):
		str = "ServerAuth"
	case X509ExtKeyUsage(x509.ExtKeyUsageClientAuth):
		str = "ClientAuth"
	case X509ExtKeyUsage(x509.ExtKeyUsageCodeSigning):
		str = "CodeSigning"
	case X509ExtKeyUsage(x509.ExtKeyUsageEmailProtection):
		str = "EmailProtection"
	case X509ExtKeyUsage(x509.ExtKeyUsageIPSECEndSystem):
		str = "IPSECEndSystem"
	case X509ExtKeyUsage(x509.ExtKeyUsageIPSECTunnel):
		str = "IPSECTunnel"
	case X509ExtKeyUsage(x509.ExtKeyUsageIPSECUser):
		str = "IPSECUser"
	case X509ExtKeyUsage(x509.ExtKeyUsageTimeStamping):
		str = "TimeStamping"
	case X509ExtKeyUsage(x509.ExtKeyUsageOCSPSigning):
		str = "OCSPSigning"
	}

	return json.Marshal(str)
}

func (c *X509ExtKeyUsage) UnmarshalJSON(data []byte) error {
	var usage X509ExtKeyUsage

	var singleUsage string
	err := json.Unmarshal(data, &singleUsage)
	if err != nil {
		if err != nil {
			return fmt.Errorf("invalid format")
		}

	}

	switch singleUsage {
	case "Any":
		usage = X509ExtKeyUsage(x509.ExtKeyUsageAny)
	case "ServerAuth":
		usage = X509ExtKeyUsage(x509.ExtKeyUsageServerAuth)
	case "ClientAuth":
		usage = X509ExtKeyUsage(x509.ExtKeyUsageClientAuth)
	case "CodeSigning":
		usage = X509ExtKeyUsage(x509.ExtKeyUsageCodeSigning)
	case "EmailProtection":
		usage = X509ExtKeyUsage(x509.ExtKeyUsageEmailProtection)
	case "IPSECEndSystem":
		usage = X509ExtKeyUsage(x509.ExtKeyUsageIPSECEndSystem)
	case "IPSECTunnel":
		usage = X509ExtKeyUsage(x509.ExtKeyUsageIPSECTunnel)
	case "IPSECUser":
		usage = X509ExtKeyUsage(x509.ExtKeyUsageIPSECUser)
	case "TimeStamping":
		usage = X509ExtKeyUsage(x509.ExtKeyUsageTimeStamping)
	case "OCSPSigning":
		usage = X509ExtKeyUsage(x509.ExtKeyUsageOCSPSigning)
	default:
		return fmt.Errorf("unknown extended key usage: %s", singleUsage)
	}

	c = &usage

	return nil
}
