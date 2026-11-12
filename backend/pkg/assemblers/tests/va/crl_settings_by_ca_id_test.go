package va

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/backend/pkg/assemblers/tests"
	bhelpers "github.com/lamassuiot/lamassuiot/v4/backend/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	chelpers "github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"
)

func revokedSerials(crl *x509.RevocationList) []string {
	var out []string
	for _, e := range crl.RevokedCertificateEntries {
		out = append(out, bhelpers.SerialNumberToHexString(e.SerialNumber))
	}
	return out
}

// Two CAs with the same subject and the same key are the case a verifier cannot tell apart: both CRLs verify against
// both CAs. Each one must list its own revocations, and the CDP of what a CA issues must lead to its own CRL.
func TestCRLsOfCAsWithTheSameSubjectAndKeyListOnlyTheirOwnRevocations(t *testing.T) {
	require.NoError(t, serverTest.BeforeEach())
	ctx := context.Background()
	caSvc := serverTest.CA.Service
	first, err := initCAForVA(caSvc)
	require.NoError(t, err)
	second, err := caSvc.CreateCA(ctx, services.CreateCAInput{
		KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048, KeyID: "pkcs11:token-id=" + first.Certificate.EngineID + ";id=" + first.Certificate.KeyID + ";type=private"},
		Subject:      models.Subject{CommonName: "TestCA"},
		CAExpiration: models.Validity{Type: models.Duration, Duration: models.TimeDuration(24 * time.Hour)},
		ProfileID:    first.ProfileID,
	})
	require.NoError(t, err)
	waitForInitialCRL(t, first.ID)
	waitForInitialCRL(t, second.ID)

	issueAndRevoke := func(ca *models.CACertificate) *models.Certificate {
		key, err := chelpers.GenerateRSAKey(2048)
		require.NoError(t, err)
		csr, err := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "leaf of " + ca.ID}, key)
		require.NoError(t, err)
		crt, err := caSvc.SignCertificate(ctx, services.SignCertificateInput{CAID: ca.ID, CertRequest: (*models.X509CertificateRequest)(csr), IssuanceProfileID: ca.ProfileID})
		require.NoError(t, err)
		cdps := ((*x509.Certificate)(crt.Certificate)).CRLDistributionPoints
		require.True(t, slices.ContainsFunc(cdps, func(u string) bool { return strings.HasSuffix(u, "/crl/"+ca.ID) }), "the CDP is the URL of the CRL of the issuer CA: %v", cdps)
		_, err = caSvc.UpdateCertificateStatus(ctx, services.UpdateCertificateStatusInput{SerialNumber: crt.SerialNumber, NewStatus: models.StatusRevoked, RevocationReason: ocsp.Unspecified})
		require.NoError(t, err)
		return crt
	}
	revokedByFirst, revokedBySecond := issueAndRevoke(first), issueAndRevoke(second)

	for _, tc := range []struct {
		ca   *models.CACertificate
		want string
	}{{first, revokedByFirst.SerialNumber}, {second, revokedBySecond.SerialNumber}} {
		require.NoError(t, tests.SleepRetry(5, 3*time.Second, func() error {
			crl, err := serverTest.VA.HttpVASDK.GetCRL(ctx, services.GetCRLResponseInput{ID: tc.ca.ID, Issuer: (*x509.Certificate)(tc.ca.Certificate.Certificate), VerifyResponse: true})
			if err != nil {
				return err
			}
			if got := revokedSerials(crl); len(got) != 1 || got[0] != tc.want {
				return fmt.Errorf("CRL of %s lists %v, want only %s", tc.ca.ID, got, tc.want)
			}
			return nil
		}))
	}
}

// A certificate issued before the settings moved to the CA ID has /crl/<ski> as CDP: it keeps resolving to the CRL of
// the CA, and the CRL announces both URLs in its IDP.
func TestLegacySKIURLServesTheCRLOfTheMigratedCA(t *testing.T) {
	require.NoError(t, serverTest.BeforeEach())
	ctx := context.Background()
	ca, err := initCAForVA(serverTest.CA.Service)
	require.NoError(t, err)
	waitForInitialCRL(t, ca.ID)
	// What the migration does to the settings that were keyed by SKI.
	require.NoError(t, vaSchemaDB(t).Exec(`UPDATE crl_settings SET legacy_ski = ? WHERE ca_id = ?`, ca.Certificate.SubjectKeyID, ca.ID).Error)

	_, err = serverTest.VA.CRLService.CalculateCRL(ctx, services.CalculateCRLInput{CAID: ca.ID})
	require.NoError(t, err)

	byID, err := serverTest.VA.HttpVASDK.GetCRL(ctx, services.GetCRLResponseInput{ID: ca.ID})
	require.NoError(t, err)
	bySKI, err := serverTest.VA.HttpVASDK.GetCRL(ctx, services.GetCRLResponseInput{ID: ca.Certificate.SubjectKeyID})
	require.NoError(t, err)
	require.True(t, bytes.Equal(byID.Raw, bySKI.Raw), "both URLs serve the same CRL")

	var idp []byte
	for _, ext := range byID.Extensions {
		if ext.Id.String() == "2.5.29.28" {
			idp = ext.Value
		}
	}
	require.Contains(t, string(idp), "/crl/"+ca.ID)
	require.Contains(t, string(idp), "/crl/"+ca.Certificate.SubjectKeyID)
}

func TestArchivedCRLSettingsServeTheirCRLButCannotBeChanged(t *testing.T) {
	require.NoError(t, serverTest.BeforeEach())
	ctx := context.Background()
	ca, err := initCAForVA(serverTest.CA.Service)
	require.NoError(t, err)
	settings := waitForInitialCRL(t, ca.ID)
	require.NoError(t, vaSchemaDB(t).Exec(`UPDATE crl_settings SET status = 'ARCHIVED' WHERE ca_id = ?`, ca.ID).Error)

	_, err = serverTest.VA.HttpVASDK.UpdateCRLSettings(ctx, services.UpdateCRLSettingsInput{CAID: ca.ID, Options: settings.Options})
	require.ErrorIs(t, err, errs.ErrCRLSettingsNotActive)
	_, err = serverTest.VA.CRLService.CalculateCRL(ctx, services.CalculateCRLInput{CAID: ca.ID})
	require.ErrorIs(t, err, errs.ErrCRLSettingsNotActive)

	crl, err := serverTest.VA.HttpVASDK.GetCRL(ctx, services.GetCRLResponseInput{ID: ca.ID})
	require.NoError(t, err)
	require.Equal(t, settings.LatestCRL.Version.String(), crl.Number.String())
}
