package models

import (
	"encoding/json"
	"fmt"
	"strings"
)

type RevocationReason int

var RevocationReasonMap = map[int]string{
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
	if reason, ok := RevocationReasonMap[int(p)]; ok {
		return []byte(reason), nil
	}

	return nil, fmt.Errorf("unsupported revocation code")
}

func (p *RevocationReason) UnmarshalText(text []byte) (err error) {
	pw := string(text)

	for k, v := range RevocationReasonMap {
		if strings.EqualFold(strings.ToLower(v), strings.ToLower(pw)) {
			*p = RevocationReason(k)
			return nil
		}
	}

	return fmt.Errorf("unsupported revocation code")
}

func (c RevocationReason) String() string {
	r, err := c.MarshalText()
	if err != nil {
		return "-"
	}

	return string(r)
}

func (c RevocationReason) MarshalJSON() ([]byte, error) {
	r, err := c.MarshalText()
	if err != nil {
		return nil, err
	}
	return json.Marshal(string(r))
}

func (c *RevocationReason) UnmarshalJSON(data []byte) error {
	var rStr string
	json.Unmarshal(data, &rStr)

	return c.UnmarshalText([]byte(rStr))
}
