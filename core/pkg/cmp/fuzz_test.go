package cmp_test

import (
	"testing"

	cmp "github.com/lamassuiot/lamassuiot/core/v3/pkg/cmp"
)

func FuzzParseMessage(f *testing.F) {
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x02})
	f.Fuzz(func(t *testing.T, der []byte) {
		_, _ = cmp.ParseRawMessage(der)
		_, _ = cmp.ParseMessage(der)
	})
}

func FuzzCMPBodyDecoders(f *testing.F) {
	f.Add([]byte{0x30, 0x00})
	f.Fuzz(func(t *testing.T, der []byte) {
		_, _ = cmp.DecodeFirstCertReq(der)
		_, _ = cmp.DecodeRevDetails(der)
		_, _ = cmp.DecodePollReqContent(der)
		_, _ = cmp.DecodeCertConfStatuses(der)
		_, _ = cmp.FindFirstOctetString(der)
	})
}
