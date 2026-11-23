package upgradecheck

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	vaSignerCheck    = "va signer"
	vaURLIDCheck     = "va ca ids in urls"
	vaSharedSKICheck = "va shared ski"
	vaSignerKeyCheck = "va signer key"
	vaArchivedID     = "va archived settings id"
	vaAmbiguousURL   = "va ambiguous crl urls"
)

// vaScenario is a 3.8 installation and the problems the VA checks must report on it, by check name.
type vaScenario struct {
	name  string
	setup func(f *fixture) map[string][]string
}

func noKeyMessage(roleSKI, caID, serial string) string {
	return fmt.Sprintf("VA role %s, CA %s: signer certificate %s has no key, so it cannot sign CRLs. Point the role to a signer with a key, or fix the key reference of the certificate, before upgrading", roleSKI, caID, serial)
}

var vaScenarios = []vaScenario{
	{"clean", func(f *fixture) map[string][]string {
		ski := f.cert("c-a", "fs")
		f.ca("ca-a", "c-a", "2020-01-01")
		f.role(ski, ski)
		return map[string][]string{}
	}},
	{"unresolved signer", func(f *fixture) map[string][]string {
		ski := f.cert("c-a", "fs")
		f.ca("ca-a", "c-a", "2020-01-01")
		f.role(ski, "deadbeef")
		return map[string][]string{vaSignerCheck: {fmt.Sprintf("cannot resolve signer certificate for VA role %s, SKI deadbeef: 0 candidates: none", ski)}}
	}},
	{"orphan resolves through the fallback", func(f *fixture) map[string][]string {
		ski := f.cert("c-orph", "fs") // its CA was deleted: the certificate is left, the CA row is gone
		f.role(ski, ski)
		return map[string][]string{}
	}},
	{"slash in CA id", func(f *fixture) map[string][]string {
		ski := f.cert("c-a", "fs")
		f.ca("team/root", "c-a", "2020-01-01")
		f.role(ski, ski)
		return map[string][]string{vaURLIDCheck: {`CA ids containing "/" cannot be used in CRL URLs: team/root. Recreate these CAs with a different id before upgrading`}}
	}},
	{"SKI shared by two CAs", func(f *fixture) map[string][]string {
		ski := f.cert("c-1", "fs")
		f.rawCertLike("c-2", "c-1")
		f.ca("ca-1", "c-1", "2020-01-01")
		f.ca("ca-2", "c-2", "2021-01-01")
		f.role(ski, ski)
		return map[string][]string{vaSharedSKICheck: {fmt.Sprintf("VA role %s: SKI shared by CAs ca-1, ca-2. Every SKI must belong to a single CA before upgrading: recreate all but one of them on a different key", ski)}}
	}},
	{"signer without key", func(f *fixture) map[string][]string {
		ski := f.cert("c-a", "")
		f.ca("ca-a", "c-a", "2020-01-01")
		f.role(ski, ski)
		return map[string][]string{vaSignerKeyCheck: {noKeyMessage(ski, "ca-a", "c-a")}}
	}},
	{"shared signer SKI: the oldest CA signs", func(f *fixture) map[string][]string {
		skiX := f.cert("c-x", "fs")
		f.ca("ca-x", "c-x", "2020-01-01")
		signerSKI := f.cert("c-old", "") // the oldest CA with the signer SKI signs, and it has no key
		f.rawCertLike("c-new", "c-old")
		f.ca("ca-new", "c-new", "2022-01-01")
		f.ca("ca-old", "c-old", "2019-01-01")
		f.role(skiX, signerSKI)
		return map[string][]string{vaSignerKeyCheck: {noKeyMessage(skiX, "ca-x", "c-old")}}
	}},
	{"undecodable signer", func(f *fixture) map[string][]string {
		f.rawCert("c-a", "abcd", "fs", "not a certificate")
		f.ca("ca-a", "c-a", "2020-01-01")
		f.role("abcd", "abcd")
		return map[string][]string{vaSignerKeyCheck: {noKeyMessage("abcd", "ca-a", "c-a")}}
	}},
	{"CA id reserved for archived settings", func(f *fixture) map[string][]string {
		orphan := f.cert("c-orph", "fs")
		f.role(orphan, orphan)
		f.cert("c-x", "fs")
		f.ca("legacy-"+orphan, "c-x", "2020-01-01")
		return map[string][]string{vaArchivedID: {fmt.Sprintf("VA role %s: CA legacy-%s has the id reserved for the archived settings of this role, whose CA was deleted. Recreate that CA with a different id before upgrading", orphan, orphan)}}
	}},
	{"CA id equal to the SKI of another role", func(f *fixture) map[string][]string {
		skiA := f.cert("c-a", "fs")
		skiB := f.cert("c-b", "fs")
		f.ca(skiB, "c-a", "2020-01-01") // CA of skiA, whose id is the SKI of the role of another CA
		f.ca("ca-b", "c-b", "2021-01-01")
		f.role(skiA, skiA)
		f.role(skiB, skiB)
		return map[string][]string{vaAmbiguousURL: {fmt.Sprintf("CA ids equal to the SKI of another VA role: %s. Their CRL URLs would be ambiguous", skiB)}}
	}},
}

func runVAChecks(t *testing.T, f *fixture) map[string][]string {
	t.Helper()
	return problemsByCheck(t, RunChecks(context.Background(), f.env, VAChecks()))
}

func TestVAChecksCoverTheVAMigrations(t *testing.T) {
	names := []string{}
	for _, c := range VAChecks() {
		names = append(names, c.Name)
	}
	require.Equal(t, []string{vaSignerCheck, vaURLIDCheck, vaSharedSKICheck, vaSignerKeyCheck, vaArchivedID, vaAmbiguousURL}, names)
	require.Equal(t, []string{"va/20261104121000_va_role_signer_certificate"}, VAChecks()[0].Covers)
	for _, c := range VAChecks()[1:] {
		require.Equal(t, []string{"va/20261111120000_crl_settings"}, c.Covers, c.Name)
	}
}

func TestVAChecks(t *testing.T) {
	for _, sc := range vaScenarios {
		t.Run(sc.name, func(t *testing.T) {
			f := newFixture(t)
			want := sc.setup(f)
			require.Equal(t, want, runVAChecks(t, f))
		})
	}
}

func TestVAChecksReportAllConditionsTogether(t *testing.T) {
	f := newFixture(t)
	ski := f.cert("c-a", "fs")
	f.ca("team/root", "c-a", "2020-01-01")
	f.role(ski, ski)
	orphan := f.cert("c-orph", "fs")
	f.role(orphan, orphan)
	f.cert("c-x", "fs")
	f.ca("legacy-"+orphan, "c-x", "2020-01-01")

	problems := runVAChecks(t, f)
	require.Contains(t, problems, vaURLIDCheck)
	require.Contains(t, problems, vaArchivedID)
}
