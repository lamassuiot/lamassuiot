package models

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strings"
)

type X509KeyUsage x509.KeyUsage

func (p X509KeyUsage) MarshalJSON() ([]byte, error) {
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

	*c = X509KeyUsage(usages)
	return nil
}

type X509ExtKeyUsage x509.ExtKeyUsage

var X509ExtKeyUsageMap = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny:                            "Any",
	x509.ExtKeyUsageServerAuth:                     "ServerAuth",
	x509.ExtKeyUsageClientAuth:                     "ClientAuth",
	x509.ExtKeyUsageCodeSigning:                    "CodeSigning",
	x509.ExtKeyUsageEmailProtection:                "EmailProtection",
	x509.ExtKeyUsageIPSECEndSystem:                 "IPSECEndSystem",
	x509.ExtKeyUsageIPSECTunnel:                    "IPSECTunnel",
	x509.ExtKeyUsageIPSECUser:                      "IPSECUser",
	x509.ExtKeyUsageTimeStamping:                   "TimeStamping",
	x509.ExtKeyUsageOCSPSigning:                    "OCSPSigning",
	x509.ExtKeyUsageMicrosoftServerGatedCrypto:     "MicrosoftServerGatedCrypto",
	x509.ExtKeyUsageNetscapeServerGatedCrypto:      "NetscapeServerGatedCrypto",
	x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "MicrosoftCommercialCodeSigning",
}

func (p X509ExtKeyUsage) MarshalText() ([]byte, error) {
	if value, ok := X509ExtKeyUsageMap[x509.ExtKeyUsage(p)]; ok {
		return []byte(value), nil
	}

	return nil, fmt.Errorf("unsupported ext key usage")
}

func (p *X509ExtKeyUsage) UnmarshalText(text []byte) (err error) {
	pw := string(text)

	for k, v := range X509ExtKeyUsageMap {
		if strings.EqualFold(strings.ToLower(v), strings.ToLower(pw)) {
			*p = X509ExtKeyUsage(k)
			return nil
		}
	}

	return fmt.Errorf("unsupported ext key usage")
}

func (c X509ExtKeyUsage) String() string {
	r, err := c.MarshalText()
	if err != nil {
		return "-"
	}

	return string(r)
}
