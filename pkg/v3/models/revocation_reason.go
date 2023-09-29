package models

import (
	"fmt"
	"strings"
)

type RevocationReason int

var revocationReasonMap = map[int]string{
	0: "Unspecified",
	1: "KeyCompromise",
	2: "CACompromise",
	3: "AffiliationChanged",
	4: "Superseded",
	5: "CessationOfOperation",
	6: "CertificateHold",
	//7 not specified in RFC
	8:  "RemoveFromCRL",
	9:  "PrivilegeWithdrawn",
	10: "AACompromise",
}

func (p RevocationReason) MarshalText() ([]byte, error) {
	if reason, ok := revocationReasonMap[int(p)]; ok {
		return []byte(reason), nil
	}

	return nil, fmt.Errorf("unsupported revocation code")
}

func (p *RevocationReason) UnmarshalText(text []byte) (err error) {
	pw := string(text)

	for k, v := range revocationReasonMap {
		if strings.EqualFold(v, pw) {
			p = (*RevocationReason)(&k)
			return nil
		}
	}

	return fmt.Errorf("unsupported revocation code")
}
