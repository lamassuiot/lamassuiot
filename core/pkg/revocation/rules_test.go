package revocation

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestCheckFreshness(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name       string
		thisUpdate time.Time
		nextUpdate time.Time
		fresh      bool
	}{
		{"OK/WithinWindow", now.Add(-time.Hour), now.Add(time.Hour), true},
		{"OK/NextUpdateJustPassedWithinSkew", now.Add(-time.Hour), now.Add(-time.Minute), true},
		{"OK/ThisUpdateSlightlyAheadWithinSkew", now.Add(time.Minute), now.Add(time.Hour), true},
		{"OK/NoNextUpdateRecent", now.Add(-time.Hour), time.Time{}, true},
		{"Err/MissingThisUpdate", time.Time{}, now.Add(time.Hour), false},
		{"Err/ThisUpdateInFuture", now.Add(time.Hour), now.Add(2 * time.Hour), false},
		{"Err/NextUpdatePassed", now.Add(-2 * time.Hour), now.Add(-time.Hour), false},
		{"Err/NoNextUpdateTooOld", now.Add(-25 * time.Hour), time.Time{}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckFreshness(tc.thisUpdate, tc.nextUpdate, now)
			if tc.fresh && err != nil {
				t.Fatalf("expected fresh. Got %s", err)
			}
			if !tc.fresh && err == nil {
				t.Fatalf("expected not fresh. Got no error")
			}
		})
	}
}

// certWithDPs returns a certificate whose CRL distribution points extension holds dps, each one encoded by the caller.
func certWithDPs(isCA bool, dps ...[]byte) *x509.Certificate {
	cert := certWithCDP(tlv(0x30, dps...))
	cert.IsCA = isCA
	return cert
}

func idpExt(t *testing.T, idp IssuingDistributionPoint) pkix.Extension {
	t.Helper()
	value, err := MarshalIssuingDistributionPoint(idp)
	if err != nil {
		t.Fatalf("could not marshal issuing distribution point: %s", err)
	}
	return pkix.Extension{Id: OIDExtensionIssuingDistributionPoint, Critical: true, Value: value}
}

func uriDP(uri string) DistributionPointName {
	return DistributionPointName{FullName: []asn1.RawValue{URIGeneralName(uri)}}
}

func TestCheckCRLScope(t *testing.T) {
	const (
		dp     = "http://crl.example/ca"
		mirror = "http://mirror.example/ca"
	)
	keyCompromiseOnly := asn1.BitString{Bytes: []byte{0x40}, BitLength: 2}

	endEntity := certWithDPs(false, tlv(0x30, fullNameDP(dp)))
	ca := certWithDPs(true, tlv(0x30, fullNameDP(dp)))
	withMirror := certWithDPs(false, tlv(0x30, fullNameDP(dp)), tlv(0x30, fullNameDP(mirror)))
	reasonsOnly := certWithDPs(false, tlv(0x30, fullNameDP(dp), []byte{0x81, 0x02, 0x06, 0x40}))
	malformedCDP := certWithDPs(false, tlv(0x30, fullNameDP(dp), []byte{0x81, 0x00}))

	baseCRLNumber, err := asn1.Marshal(big.NewInt(1))
	if err != nil {
		t.Fatalf("could not marshal CRL number: %s", err)
	}
	validIDP := idpExt(t, IssuingDistributionPoint{DistributionPoint: uriDP(dp)})
	trailingIDP := validIDP
	trailingIDP.Value = append(slices.Clone(validIDP.Value), 0x00)

	tests := []struct {
		name    string
		exts    []pkix.Extension
		cert    *x509.Certificate
		crlDP   string
		wantErr string
	}{
		{name: "OK/NoExtensions", cert: endEntity, crlDP: dp},
		{name: "OK/IDPNamesDistributionPoint", exts: []pkix.Extension{validIDP}, cert: endEntity, crlDP: dp},
		{name: "OK/IDPNamesMirror", exts: []pkix.Extension{idpExt(t, IssuingDistributionPoint{DistributionPoint: uriDP(mirror)})}, cert: withMirror, crlDP: dp},
		{name: "OK/OnlyUserCertsEndEntity", exts: []pkix.Extension{idpExt(t, IssuingDistributionPoint{DistributionPoint: uriDP(dp), OnlyContainsUserCerts: true})}, cert: endEntity, crlDP: dp},
		{name: "OK/OnlyCACertsCA", exts: []pkix.Extension{idpExt(t, IssuingDistributionPoint{DistributionPoint: uriDP(dp), OnlyContainsCACerts: true})}, cert: ca, crlDP: dp},
		{name: "OK/IDPWithoutDistributionPoint", exts: []pkix.Extension{idpExt(t, IssuingDistributionPoint{})}, cert: endEntity, crlDP: dp},
		{
			name:    "Err/DeltaCRL",
			exts:    []pkix.Extension{{Id: OIDExtensionDeltaCRLIndicator, Critical: true, Value: baseCRLNumber}},
			cert:    endEntity,
			crlDP:   dp,
			wantErr: "delta CRL",
		},
		{
			name:    "Err/OnlyUserCertsCA",
			exts:    []pkix.Extension{idpExt(t, IssuingDistributionPoint{DistributionPoint: uriDP(dp), OnlyContainsUserCerts: true})},
			cert:    ca,
			crlDP:   dp,
			wantErr: "only covers end-entity",
		},
		{
			name:    "Err/OnlyCACertsEndEntity",
			exts:    []pkix.Extension{idpExt(t, IssuingDistributionPoint{DistributionPoint: uriDP(dp), OnlyContainsCACerts: true})},
			cert:    endEntity,
			crlDP:   dp,
			wantErr: "only covers CA certificates",
		},
		{
			name:    "Err/OnlySomeReasons",
			exts:    []pkix.Extension{idpExt(t, IssuingDistributionPoint{DistributionPoint: uriDP(dp), OnlySomeReasons: keyCompromiseOnly})},
			cert:    endEntity,
			crlDP:   dp,
			wantErr: "restricts the CRL scope",
		},
		{
			// A present onlySomeReasons with no bit set covers no reason at all.
			name:    "Err/OnlySomeReasonsNoBits",
			exts:    []pkix.Extension{idpExt(t, IssuingDistributionPoint{DistributionPoint: uriDP(dp), OnlySomeReasons: asn1.BitString{Bytes: []byte{}}})},
			cert:    endEntity,
			crlDP:   dp,
			wantErr: "restricts the CRL scope",
		},
		{
			name:    "Err/IndirectCRL",
			exts:    []pkix.Extension{idpExt(t, IssuingDistributionPoint{DistributionPoint: uriDP(dp), IndirectCRL: true})},
			cert:    endEntity,
			crlDP:   dp,
			wantErr: "restricts the CRL scope",
		},
		{
			name:    "Err/OnlyAttributeCerts",
			exts:    []pkix.Extension{idpExt(t, IssuingDistributionPoint{DistributionPoint: uriDP(dp), OnlyContainsAttributeCerts: true})},
			cert:    endEntity,
			crlDP:   dp,
			wantErr: "restricts the CRL scope",
		},
		{
			name:    "Err/OtherPartition",
			exts:    []pkix.Extension{idpExt(t, IssuingDistributionPoint{DistributionPoint: uriDP(dp + "/partition-2")})},
			cert:    endEntity,
			crlDP:   dp,
			wantErr: "does not match any CRL distribution point",
		},
		{
			name:    "Err/RelativeNameOnly",
			exts:    []pkix.Extension{{Id: OIDExtensionIssuingDistributionPoint, Critical: true, Value: tlv(0x30, relativeNameDP())}},
			cert:    endEntity,
			crlDP:   dp,
			wantErr: "does not match any CRL distribution point",
		},
		{
			name:    "Err/MalformedIDP",
			exts:    []pkix.Extension{{Id: OIDExtensionIssuingDistributionPoint, Critical: true, Value: []byte{0x30, 0x03, 0x01}}},
			cert:    endEntity,
			crlDP:   dp,
			wantErr: "malformed issuing distribution point extension",
		},
		{
			name:    "Err/IDPTrailingData",
			exts:    []pkix.Extension{trailingIDP},
			cert:    endEntity,
			crlDP:   dp,
			wantErr: "malformed issuing distribution point extension",
		},
		{
			name:    "Err/DistributionPointWithReasons",
			cert:    reasonsOnly,
			crlDP:   dp,
			wantErr: "only covers some revocation reasons",
		},
		{
			name:    "Err/CRLDPNotInCertificate",
			cert:    endEntity,
			crlDP:   "http://elsewhere.example/ca",
			wantErr: "only covers some revocation reasons",
		},
		{
			name:    "Err/MalformedCDP",
			cert:    malformedCDP,
			crlDP:   dp,
			wantErr: "malformed CRL distribution points extension",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckCRLScope(&x509.RevocationList{Extensions: tc.exts}, tc.cert, tc.crlDP)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected no error. Got %s", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q. Got %v", tc.wantErr, err)
			}
		})
	}
}
