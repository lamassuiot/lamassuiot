package revocation

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"slices"
	"testing"
)

// tlv encodes a DER element with a short-form length.
func tlv(tag byte, content ...[]byte) []byte {
	value := bytes.Join(content, nil)
	if len(value) >= 0x80 {
		panic("tlv only supports short-form lengths")
	}
	return append([]byte{tag, byte(len(value))}, value...)
}

// uriName encodes a GeneralName uniformResourceIdentifier.
func uriName(uri string) []byte {
	return tlv(0x86, []byte(uri))
}

// fullNameDP encodes the [0] DistributionPointName of a distribution point holding fullName.
func fullNameDP(uris ...string) []byte {
	var names [][]byte
	for _, uri := range uris {
		names = append(names, uriName(uri))
	}
	return tlv(0xa0, tlv(0xa0, names...))
}

// relativeNameDP encodes the [0] DistributionPointName of a distribution point holding nameRelativeToCRLIssuer CN=crl.
// It is a single RelativeDistinguishedName whose SET OF tag the IMPLICIT [1] replaces (RFC 5280 4.2.1.13, A.2): no
// SEQUENCE OF wraps it, unlike a Name.
func relativeNameDP() []byte {
	cn := tlv(0x30, tlv(0x06, []byte{0x55, 0x04, 0x03}), tlv(0x13, []byte("crl")))
	return tlv(0xa0, tlv(0xa1, cn))
}

func uris(names []asn1.RawValue) []string {
	var out []string
	for _, name := range names {
		out = append(out, string(name.Bytes))
	}
	return out
}

func TestMarshalIssuingDistributionPointIsDER(t *testing.T) {
	tests := []struct {
		name string
		idp  IssuingDistributionPoint
		want []byte
	}{
		{
			name: "OnlyURI",
			idp:  IssuingDistributionPoint{DistributionPoint: DistributionPointName{FullName: []asn1.RawValue{URIGeneralName("http://va/crl/x")}}},
			// No 81 01 00, 82 01 00, 84 01 00 or 85 01 00: DER omits DEFAULT FALSE fields (X.690 11.5).
			want: tlv(0x30, fullNameDP("http://va/crl/x")),
		},
		{
			name: "Empty",
			idp:  IssuingDistributionPoint{},
			want: []byte{0x30, 0x00},
		},
		{
			name: "RelativeName",
			idp: IssuingDistributionPoint{DistributionPoint: DistributionPointName{
				RelativeName: pkix.RelativeDistinguishedNameSET{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "crl"}},
			}},
			want: tlv(0x30, relativeNameDP()),
		},
		{
			name: "AllBooleansTrue",
			idp:  IssuingDistributionPoint{OnlyContainsUserCerts: true, OnlyContainsCACerts: true, IndirectCRL: true, OnlyContainsAttributeCerts: true},
			want: tlv(0x30, []byte{0x81, 0x01, 0xff, 0x82, 0x01, 0xff, 0x84, 0x01, 0xff, 0x85, 0x01, 0xff}),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := MarshalIssuingDistributionPoint(tc.idp)
			if err != nil {
				t.Fatalf("expected no error. Got %s", err)
			}
			if !bytes.Equal(got, tc.want) {
				t.Fatalf("expected % x. Got % x", tc.want, got)
			}
		})
	}
}

func TestParseIssuingDistributionPoint(t *testing.T) {
	keyCompromiseOnly := asn1.BitString{Bytes: []byte{0x40}, BitLength: 2}
	allFields, err := MarshalIssuingDistributionPoint(IssuingDistributionPoint{
		DistributionPoint:          DistributionPointName{FullName: []asn1.RawValue{URIGeneralName("http://a/crl"), URIGeneralName("http://b/crl")}},
		OnlyContainsUserCerts:      true,
		OnlyContainsCACerts:        true,
		OnlySomeReasons:            keyCompromiseOnly,
		IndirectCRL:                true,
		OnlyContainsAttributeCerts: true,
	})
	if err != nil {
		t.Fatalf("could not marshal: %s", err)
	}
	uriOnly := tlv(0x30, fullNameDP("http://va/crl/x"))

	t.Run("OK/RoundTripAllFields", func(t *testing.T) {
		idp, err := ParseIssuingDistributionPoint(allFields)
		if err != nil {
			t.Fatalf("expected no error. Got %s", err)
		}
		if got := uris(idp.DistributionPoint.FullName); !slices.Equal(got, []string{"http://a/crl", "http://b/crl"}) {
			t.Fatalf("unexpected full name %v", got)
		}
		if !idp.OnlyContainsUserCerts || !idp.OnlyContainsCACerts || !idp.IndirectCRL || !idp.OnlyContainsAttributeCerts {
			t.Fatalf("expected every boolean set. Got %+v", idp)
		}
		if !bytes.Equal(idp.OnlySomeReasons.Bytes, keyCompromiseOnly.Bytes) || idp.OnlySomeReasons.BitLength != keyCompromiseOnly.BitLength {
			t.Fatalf("unexpected onlySomeReasons %+v", idp.OnlySomeReasons)
		}
	})

	// The encoding of the VA before issue #889, which spelled out its DEFAULT FALSE booleans. CRLs published with it
	// must keep parsing.
	t.Run("OK/LegacyExplicitFalse", func(t *testing.T) {
		legacy := tlv(0x30, fullNameDP("http://va/crl/x"), []byte{0x81, 0x01, 0x00, 0x82, 0x01, 0x00, 0x84, 0x01, 0x00, 0x85, 0x01, 0x00})
		idp, err := ParseIssuingDistributionPoint(legacy)
		if err != nil {
			t.Fatalf("expected no error. Got %s", err)
		}
		if got := uris(idp.DistributionPoint.FullName); !slices.Equal(got, []string{"http://va/crl/x"}) {
			t.Fatalf("unexpected full name %v", got)
		}
		if idp.OnlyContainsUserCerts || idp.OnlyContainsCACerts || idp.IndirectCRL || idp.OnlyContainsAttributeCerts || idp.OnlySomeReasons.Bytes != nil {
			t.Fatalf("expected no restriction. Got %+v", idp)
		}
	})

	t.Run("OK/RelativeName", func(t *testing.T) {
		der := tlv(0x30, relativeNameDP())
		idp, err := ParseIssuingDistributionPoint(der)
		if err != nil {
			t.Fatalf("expected no error. Got %s", err)
		}
		got, err := MarshalIssuingDistributionPoint(idp)
		if err != nil {
			t.Fatalf("could not marshal: %s", err)
		}
		if !bytes.Equal(got, der) {
			t.Fatalf("expected % x. Got % x", der, got)
		}
	})

	for _, tc := range []struct {
		name string
		der  []byte
	}{
		{"Err/Truncated", []byte{0x30, 0x03, 0x01}},
		{"Err/TrailingData", append(slices.Clone(uriOnly), 0x00)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseIssuingDistributionPoint(tc.der)
			if err == nil || err.Error() != "malformed issuing distribution point extension" {
				t.Fatalf("expected malformed issuing distribution point error. Got %v", err)
			}
		})
	}
}

func certWithCDP(value []byte) *x509.Certificate {
	return &x509.Certificate{Extensions: []pkix.Extension{{Id: OIDExtensionCRLDistributionPoints, Value: value}}}
}

func TestAllReasonsDistributionPoints(t *testing.T) {
	keyCompromiseOnly := []byte{0x81, 0x02, 0x06, 0x40}
	// [1] BIT STRING with no content, which DER forbids.
	malformedReasons := []byte{0x81, 0x00}

	tests := []struct {
		name string
		cert *x509.Certificate
		want []string
		err  bool
	}{
		{name: "OK/NoExtension", cert: &x509.Certificate{}},
		{
			name: "OK/EveryURIInOrder",
			cert: certWithCDP(tlv(0x30, tlv(0x30, fullNameDP("http://a/crl", "http://b/crl")), tlv(0x30, fullNameDP("http://c/crl")))),
			want: []string{"http://a/crl", "http://b/crl", "http://c/crl"},
		},
		{
			name: "OK/SkipsDistributionPointWithReasons",
			cert: certWithCDP(tlv(0x30, tlv(0x30, fullNameDP("http://a/crl"), keyCompromiseOnly), tlv(0x30, fullNameDP("http://b/crl")))),
			want: []string{"http://b/crl"},
		},
		{
			// A distribution point named relative to the CRL issuer has no URI to fetch.
			name: "OK/SkipsRelativeName",
			cert: certWithCDP(tlv(0x30, tlv(0x30, relativeNameDP()), tlv(0x30, fullNameDP("http://b/crl")))),
			want: []string{"http://b/crl"},
		},
		{
			name: "Err/MalformedReasons",
			cert: certWithCDP(tlv(0x30, tlv(0x30, fullNameDP("http://a/crl"), malformedReasons))),
			err:  true,
		},
		{
			name: "Err/TrailingData",
			cert: certWithCDP(append(tlv(0x30, tlv(0x30, fullNameDP("http://a/crl"))), 0x00)),
			err:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := AllReasonsDistributionPoints(tc.cert)
			if tc.err {
				if err == nil || err.Error() != "malformed CRL distribution points extension" {
					t.Fatalf("expected malformed CRL distribution points error. Got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected no error. Got %s", err)
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("expected %v. Got %v", tc.want, got)
			}
		})
	}
}

func TestParseCRLDistributionPointsKeepsReasonsAndCRLIssuer(t *testing.T) {
	crlIssuer := tlv(0xa2, uriName("http://issuer"))
	cert := certWithCDP(tlv(0x30, tlv(0x30, fullNameDP("http://a/crl"), []byte{0x81, 0x02, 0x06, 0x40}, crlIssuer)))

	dps, err := ParseCRLDistributionPoints(cert)
	if err != nil {
		t.Fatalf("expected no error. Got %s", err)
	}
	if len(dps) != 1 {
		t.Fatalf("expected 1 distribution point. Got %d", len(dps))
	}
	if got := uris(dps[0].DistributionPoint.FullName); !slices.Equal(got, []string{"http://a/crl"}) {
		t.Fatalf("unexpected full name %v", got)
	}
	if !bytes.Equal(dps[0].Reasons.Bytes, []byte{0x40}) || dps[0].Reasons.BitLength != 2 {
		t.Fatalf("unexpected reasons %+v", dps[0].Reasons)
	}
	if !bytes.Equal(dps[0].CRLIssuer.FullBytes, crlIssuer) {
		t.Fatalf("expected cRLIssuer % x. Got % x", crlIssuer, dps[0].CRLIssuer.FullBytes)
	}
}
