package ca

import (
	"context"
	"crypto/x509"
	"fmt"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/assemblers/tests"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

func TestReissueCAService(t *testing.T) {
	serverTest, err := tests.TestServiceBuilder{}.WithDatabase("ca", "kms").Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	caTest := serverTest.CA

	var testcases = []struct {
		name        string
		before      func(caSDK services.CAService) (string, error) // returns caID, error
		run         func(caSDK services.CAService, caID string) (*models.CACertificate, error)
		resultCheck func(caSDK services.CAService, originalCA *models.CACertificate, reissuedCA *models.CACertificate, err error) error
	}{
		{
			name: "ERR/ReissueCA_ValidationError",
			before: func(caSDK services.CAService) (string, error) {
				return "", nil // Empty CAID to trigger validation error
			},
			run: func(caSDK services.CAService, caID string) (*models.CACertificate, error) {
				return caSDK.ReissueCA(context.Background(), services.ReissueCAInput{
					CAID: caID,
				})
			},
			resultCheck: func(caSDK services.CAService, originalCA *models.CACertificate, reissuedCA *models.CACertificate, err error) error {
				if err == errs.ErrValidateBadRequest {
					return nil // Expected error
				}
				if err == nil {
					return fmt.Errorf("expected ErrValidateBadRequest error but got none")
				}
				return fmt.Errorf("expected ErrValidateBadRequest but got: %s", err)
			},
		},
		{
			name: "ERR/ReissueCA_CANotFound",
			before: func(caSDK services.CAService) (string, error) {
				return "non-existent-ca-id", nil
			},
			run: func(caSDK services.CAService, caID string) (*models.CACertificate, error) {
				return caSDK.ReissueCA(context.Background(), services.ReissueCAInput{
					CAID: caID,
				})
			},
			resultCheck: func(caSDK services.CAService, originalCA *models.CACertificate, reissuedCA *models.CACertificate, err error) error {
				if err == errs.ErrCANotFound {
					return nil // Expected error
				}
				if err == nil {
					return fmt.Errorf("expected ErrCANotFound error but got none")
				}
				return fmt.Errorf("expected ErrCANotFound but got: %s", err)
			},
		},
		{
			name: "ERR/ReissueCA_RevokedCA",
			before: func(caSDK services.CAService) (string, error) {
				// Create a CA
				ca, err := createTestCA(caSDK, "RevokedCA", false)
				if err != nil {
					return "", err
				}

				// Revoke the CA
				_, err = caSDK.UpdateCAStatus(context.Background(), services.UpdateCAStatusInput{
					CAID:   ca.ID,
					Status: models.StatusRevoked,
				})
				if err != nil {
					return "", err
				}

				return ca.ID, nil
			},
			run: func(caSDK services.CAService, caID string) (*models.CACertificate, error) {
				return caSDK.ReissueCA(context.Background(), services.ReissueCAInput{
					CAID: caID,
				})
			},
			resultCheck: func(caSDK services.CAService, originalCA *models.CACertificate, reissuedCA *models.CACertificate, err error) error {
				if err == errs.ErrCAAlreadyRevoked {
					return nil // Expected error
				}
				if err == nil {
					return fmt.Errorf("expected ErrCAAlreadyRevoked error but got none")
				}
				return fmt.Errorf("expected ErrCAAlreadyRevoked but got: %s", err)
			},
		},
		{
			name: "ERR/ReissueCA_ExpiredCA",
			before: func(caSDK services.CAService) (string, error) {
				// Create a CA
				ca, err := createTestCA(caSDK, "ExpiredCA", true)
				if err != nil {
					return "", err
				}

				time.Sleep(time.Second)

				// Mark the CA as expired
				_, err = caSDK.UpdateCAStatus(context.Background(), services.UpdateCAStatusInput{
					CAID:   ca.ID,
					Status: models.StatusExpired,
				})
				if err != nil {
					return "", err
				}

				return ca.ID, nil
			},
			run: func(caSDK services.CAService, caID string) (*models.CACertificate, error) {
				return caSDK.ReissueCA(context.Background(), services.ReissueCAInput{
					CAID: caID,
					IssuanceProfile: &models.IssuanceProfile{
						Validity: models.Validity{
							Type:     models.Duration,
							Duration: models.TimeDuration(time.Hour * 24 * 365),
						},
						SignAsCA: true,
					},
				})
			},
			resultCheck: func(caSDK services.CAService, originalCA *models.CACertificate, reissuedCA *models.CACertificate, err error) error {
				if err == errs.ErrCAExpired {
					return nil // Expected error
				}
				if err == nil {
					return fmt.Errorf("expected ErrCAExpired error but got none")
				}
				return fmt.Errorf("expected ErrCAExpired but got: %s", err)
			},
		},
		{
			name: "OK/ReissueRootCA",
			before: func(caSDK services.CAService) (string, error) {
				// Create a root CA
				ca, err := createTestCA(caSDK, "RootCA-Reissue", false)
				if err != nil {
					return "", err
				}
				return ca.ID, nil
			},
			run: func(caSDK services.CAService, caID string) (*models.CACertificate, error) {
				return caSDK.ReissueCA(context.Background(), services.ReissueCAInput{
					CAID: caID,
				})
			},
			resultCheck: func(caSDK services.CAService, originalCA *models.CACertificate, reissuedCA *models.CACertificate, err error) error {
				if err != nil {
					return fmt.Errorf("unexpected error: %s", err)
				}

				// Verify CA ID remains the same
				if originalCA.ID != reissuedCA.ID {
					return fmt.Errorf("CA ID changed: expected %s, got %s", originalCA.ID, reissuedCA.ID)
				}

				// Verify serial number changed (this should pass - they must be different)
				if originalCA.Certificate.SerialNumber == reissuedCA.Certificate.SerialNumber {
					return fmt.Errorf("serial number should have changed but didn't: original=%s, reissued=%s", originalCA.Certificate.SerialNumber, reissuedCA.Certificate.SerialNumber)
				}

				// Verify subject is preserved
				if originalCA.Certificate.Subject.CommonName != reissuedCA.Certificate.Subject.CommonName {
					return fmt.Errorf("subject changed: expected %s, got %s",
						originalCA.Certificate.Subject.CommonName,
						reissuedCA.Certificate.Subject.CommonName)
				}

				// Verify SubjectKeyID is preserved (same key)
				if originalCA.Certificate.SubjectKeyID != reissuedCA.Certificate.SubjectKeyID {
					return fmt.Errorf("SubjectKeyID changed: expected %s, got %s",
						originalCA.Certificate.SubjectKeyID,
						reissuedCA.Certificate.SubjectKeyID)
				}

				// Verify it's still a root CA (AKI == SKI)
				if reissuedCA.Certificate.SubjectKeyID != reissuedCA.Certificate.AuthorityKeyID {
					return fmt.Errorf("reissued CA is not a root CA: SKI %s != AKI %s",
						reissuedCA.Certificate.SubjectKeyID,
						reissuedCA.Certificate.AuthorityKeyID)
				}

				// Verify status is ACTIVE
				if reissuedCA.Certificate.Status != models.StatusActive {
					return fmt.Errorf("reissued CA status is not ACTIVE: %s", reissuedCA.Certificate.Status)
				}

				// Verify profile ID is preserved
				if originalCA.ProfileID != reissuedCA.ProfileID {
					return fmt.Errorf("profile ID changed: expected %s, got %s",
						originalCA.ProfileID, reissuedCA.ProfileID)
				}

				// Verify CA type is preserved
				if originalCA.Certificate.Type != reissuedCA.Certificate.Type {
					return fmt.Errorf("CA type changed: expected %s, got %s",
						originalCA.Certificate.Type, reissuedCA.Certificate.Type)
				}

				// Verify metadata contains reissuance information
				if reissuedCA.Metadata[models.CAMetadataReissuedFromKey] != originalCA.Certificate.SerialNumber {
					return fmt.Errorf("missing or incorrect reissued-from metadata: expected %s, got %v",
						originalCA.Certificate.SerialNumber,
						reissuedCA.Metadata[models.CAMetadataReissuedFromKey])
				}

				if reissuedCA.Metadata[models.CAMetadataReissueReasonKey] != "certificate-reissuance" {
					return fmt.Errorf("missing or incorrect reissue-reason metadata: got %v",
						reissuedCA.Metadata[models.CAMetadataReissueReasonKey])
				}

				// Verify old certificate was updated with linking metadata
				oldCert, err := caSDK.GetCertificateBySerialNumber(context.Background(), services.GetCertificatesBySerialNumberInput{
					SerialNumber: originalCA.Certificate.SerialNumber,
				})
				if err != nil {
					return fmt.Errorf("could not fetch old certificate: %s", err)
				}

				if oldCert.Metadata[models.CAMetadataReissuedAsKey] != reissuedCA.Certificate.SerialNumber {
					return fmt.Errorf("old certificate missing reissued-as metadata: expected %s, got %v",
						reissuedCA.Certificate.SerialNumber,
						oldCert.Metadata[models.CAMetadataReissuedAsKey])
				}

				// Verify old certificate is still ACTIVE
				if oldCert.Status != models.StatusActive {
					return fmt.Errorf("old certificate status changed: expected ACTIVE, got %s", oldCert.Status)
				}

				return nil
			},
		},
		{
			name: "OK/ReissueSubordinateCA",
			before: func(caSDK services.CAService) (string, error) {
				// Create root CA
				rootCA, err := createTestCA(caSDK, "RootCA-Parent", false)
				if err != nil {
					return "", err
				}

				// Create subordinate CA
				subCA, err := createSubordinateCA(caSDK, rootCA.ID, "SubCA-Reissue")
				if err != nil {
					return "", err
				}

				return subCA.ID, nil
			},
			run: func(caSDK services.CAService, caID string) (*models.CACertificate, error) {
				return caSDK.ReissueCA(context.Background(), services.ReissueCAInput{
					CAID:            caID,
					IssuanceProfile: &models.IssuanceProfile{SignAsCA: true},
				})
			},
			resultCheck: func(caSDK services.CAService, originalCA *models.CACertificate, reissuedCA *models.CACertificate, err error) error {
				if err != nil {
					return fmt.Errorf("unexpected error: %s", err)
				}

				// Verify CA ID remains the same
				if originalCA.ID != reissuedCA.ID {
					return fmt.Errorf("CA ID changed: expected %s, got %s", originalCA.ID, reissuedCA.ID)
				}

				// Verify serial number changed (this should pass - they must be different)
				if originalCA.Certificate.SerialNumber == reissuedCA.Certificate.SerialNumber {
					return fmt.Errorf("serial number should have changed but didn't: original=%s, reissued=%s", originalCA.Certificate.SerialNumber, reissuedCA.Certificate.SerialNumber)
				}

				// Verify it's still a subordinate CA (AKI != SKI)
				if reissuedCA.Certificate.SubjectKeyID == reissuedCA.Certificate.AuthorityKeyID {
					return fmt.Errorf("reissued CA appears to be a root CA but should be subordinate")
				}

				// Verify parent relationship is preserved
				if originalCA.Certificate.IssuerCAMetadata.ID != reissuedCA.Certificate.IssuerCAMetadata.ID {
					return fmt.Errorf("parent CA ID changed: expected %s, got %s",
						originalCA.Certificate.IssuerCAMetadata.ID,
						reissuedCA.Certificate.IssuerCAMetadata.ID)
				}

				// Verify CA level is preserved
				if originalCA.Level != reissuedCA.Level {
					return fmt.Errorf("CA level changed: expected %d, got %d",
						originalCA.Level, reissuedCA.Level)
				}

				// Verify status is ACTIVE
				if reissuedCA.Certificate.Status != models.StatusActive {
					return fmt.Errorf("reissued CA status is not ACTIVE: %s", reissuedCA.Certificate.Status)
				}

				// Verify metadata contains reissuance information
				if reissuedCA.Metadata[models.CAMetadataReissuedFromKey] != originalCA.Certificate.SerialNumber {
					return fmt.Errorf("missing or incorrect reissued-from metadata")
				}

				return nil
			},
		},
		{
			name: "OK/ReissueCA_VerifyCRLAndOCSPURLs",
			before: func(caSDK services.CAService) (string, error) {
				// Create a CA
				ca, err := createTestCA(caSDK, "CA-CRL-OCSP-Test", false)
				if err != nil {
					return "", err
				}
				return ca.ID, nil
			},
			run: func(caSDK services.CAService, caID string) (*models.CACertificate, error) {
				return caSDK.ReissueCA(context.Background(), services.ReissueCAInput{
					CAID: caID,
				})
			},
			resultCheck: func(caSDK services.CAService, originalCA *models.CACertificate, reissuedCA *models.CACertificate, err error) error {
				if err != nil {
					return fmt.Errorf("unexpected error: %s", err)
				}

				// Parse the X.509 certificates
				origCert := (*x509.Certificate)(originalCA.Certificate.Certificate)
				reissuedCert := (*x509.Certificate)(reissuedCA.Certificate.Certificate)

				// Verify CRL Distribution Points are present
				if len(reissuedCert.CRLDistributionPoints) == 0 {
					return fmt.Errorf("reissued certificate has no CRL distribution points")
				}

				// Verify OCSP Server URLs are present
				if len(reissuedCert.OCSPServer) == 0 {
					return fmt.Errorf("reissued certificate has no OCSP server URLs")
				}

				// The URLs should be recomputed (might contain new serial number for CRL endpoint)
				// We just verify they exist and are not empty
				for _, url := range reissuedCert.CRLDistributionPoints {
					if url == "" {
						return fmt.Errorf("empty CRL distribution point URL")
					}
				}

				for _, url := range reissuedCert.OCSPServer {
					if url == "" {
						return fmt.Errorf("empty OCSP server URL")
					}
				}

				// Verify the number of URLs matches
				if len(origCert.CRLDistributionPoints) != len(reissuedCert.CRLDistributionPoints) {
					return fmt.Errorf("CRL distribution points count changed: expected %d, got %d",
						len(origCert.CRLDistributionPoints), len(reissuedCert.CRLDistributionPoints))
				}

				if len(origCert.OCSPServer) != len(reissuedCert.OCSPServer) {
					return fmt.Errorf("OCSP server count changed: expected %d, got %d",
						len(origCert.OCSPServer), len(reissuedCert.OCSPServer))
				}

				return nil
			},
		},
		{
			name: "OK/ReissueRootCA_WithInlineProfile",
			before: func(caSDK services.CAService) (string, error) {
				// Create a root CA
				ca, err := createTestCA(caSDK, "RootCA-InlineProfile", false)
				if err != nil {
					return "", err
				}
				return ca.ID, nil
			},
			run: func(caSDK services.CAService, caID string) (*models.CACertificate, error) {
				// Use inline profile for reissuance
				inlineProfile := &models.IssuanceProfile{
					Validity: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour * 24 * 365)},
					SignAsCA: true,
				}
				return caSDK.ReissueCA(context.Background(), services.ReissueCAInput{
					CAID:            caID,
					IssuanceProfile: inlineProfile,
				})
			},
			resultCheck: func(caSDK services.CAService, originalCA *models.CACertificate, reissuedCA *models.CACertificate, err error) error {
				if err != nil {
					return fmt.Errorf("unexpected error: %s", err)
				}

				// Verify CA ID remains the same
				if originalCA.ID != reissuedCA.ID {
					return fmt.Errorf("CA ID changed: expected %s, got %s", originalCA.ID, reissuedCA.ID)
				}

				// Verify serial number changed
				if originalCA.Certificate.SerialNumber == reissuedCA.Certificate.SerialNumber {
					return fmt.Errorf("serial number should have changed but didn't")
				}

				// Verify reissuance metadata is present
				if reissuedCA.Metadata[models.CAMetadataReissuedFromKey] == nil {
					return fmt.Errorf("reissuance metadata not found")
				}

				return nil
			},
		},
		{
			name: "OK/ReissueRootCA_WithProfileID",
			before: func(caSDK services.CAService) (string, error) {
				// Create a root CA
				ca, err := createTestCA(caSDK, "RootCA-ProfileID", false)
				if err != nil {
					return "", err
				}
				return ca.ID, nil
			},
			run: func(caSDK services.CAService, caID string) (*models.CACertificate, error) {
				// Create a custom issuance profile
				profile, err := caSDK.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
					Profile: models.IssuanceProfile{
						Name:     "CustomProfileForReissuance",
						Validity: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour * 24 * 365)},
						SignAsCA: true,
					},
				})
				if err != nil {
					return nil, fmt.Errorf("could not create issuance profile: %s", err)
				}

				// Reissue with profile reference
				return caSDK.ReissueCA(context.Background(), services.ReissueCAInput{
					CAID:              caID,
					IssuanceProfileID: profile.ID,
				})
			},
			resultCheck: func(caSDK services.CAService, originalCA *models.CACertificate, reissuedCA *models.CACertificate, err error) error {
				if err != nil {
					return fmt.Errorf("unexpected error: %s", err)
				}

				// Verify CA ID remains the same
				if originalCA.ID != reissuedCA.ID {
					return fmt.Errorf("CA ID changed: expected %s, got %s", originalCA.ID, reissuedCA.ID)
				}

				// Verify serial number changed
				if originalCA.Certificate.SerialNumber == reissuedCA.Certificate.SerialNumber {
					return fmt.Errorf("serial number should have changed but didn't")
				}

				// Verify reissuance metadata is present
				if reissuedCA.Metadata[models.CAMetadataReissuedFromKey] == nil {
					return fmt.Errorf("reissuance metadata not found")
				}

				return nil
			},
		},
		{
			name: "OK/ReissueCA_WithSANs",
			before: func(caSDK services.CAService) (string, error) {
				// Create a root CA
				ca, err := createTestCA(caSDK, "RootCA-WithSANs", false)
				if err != nil {
					return "", err
				}
				return ca.ID, nil
			},
			run: func(caSDK services.CAService, caID string) (*models.CACertificate, error) {
				return caSDK.ReissueCA(context.Background(), services.ReissueCAInput{
					CAID: caID,
				})
			},
			resultCheck: func(caSDK services.CAService, originalCA *models.CACertificate, reissuedCA *models.CACertificate, err error) error {
				if err != nil {
					return fmt.Errorf("unexpected error: %s", err)
				}

				// Parse the X.509 certificates
				origCert := (*x509.Certificate)(originalCA.Certificate.Certificate)
				reissuedCert := (*x509.Certificate)(reissuedCA.Certificate.Certificate)

				// Verify DNSNames are preserved
				if len(origCert.DNSNames) != len(reissuedCert.DNSNames) {
					return fmt.Errorf("DNS names count changed: expected %d, got %d",
						len(origCert.DNSNames), len(reissuedCert.DNSNames))
				}

				// Verify DNS names match
				for i, origDNS := range origCert.DNSNames {
					if i >= len(reissuedCert.DNSNames) || origDNS != reissuedCert.DNSNames[i] {
						return fmt.Errorf("DNS name %d changed: expected %s, got %s",
							i, origDNS, reissuedCert.DNSNames[i])
					}
				}

				// Verify IP addresses are preserved
				if len(origCert.IPAddresses) != len(reissuedCert.IPAddresses) {
					return fmt.Errorf("IP addresses count changed: expected %d, got %d",
						len(origCert.IPAddresses), len(reissuedCert.IPAddresses))
				}

				// Verify IP addresses match
				for i, origIP := range origCert.IPAddresses {
					if i >= len(reissuedCert.IPAddresses) || origIP.String() != reissuedCert.IPAddresses[i].String() {
						return fmt.Errorf("IP address %d changed: expected %s, got %s",
							i, origIP.String(), reissuedCert.IPAddresses[i].String())
					}
				}

				// Verify CA ID remains the same
				if originalCA.ID != reissuedCA.ID {
					return fmt.Errorf("CA ID changed: expected %s, got %s", originalCA.ID, reissuedCA.ID)
				}

				// Verify serial number changed
				if originalCA.Certificate.SerialNumber == reissuedCA.Certificate.SerialNumber {
					return fmt.Errorf("serial number should have changed but didn't")
				}

				// Verify subject is preserved
				if originalCA.Certificate.Subject.CommonName != reissuedCA.Certificate.Subject.CommonName {
					return fmt.Errorf("subject changed: expected %s, got %s",
						originalCA.Certificate.Subject.CommonName,
						reissuedCA.Certificate.Subject.CommonName)
				}

				// Verify it's still a root CA
				if reissuedCA.Certificate.SubjectKeyID != reissuedCA.Certificate.AuthorityKeyID {
					return fmt.Errorf("reissued CA is not a root CA")
				}

				// Verify status is ACTIVE
				if reissuedCA.Certificate.Status != models.StatusActive {
					return fmt.Errorf("reissued CA status is not ACTIVE: %s", reissuedCA.Certificate.Status)
				}

				return nil
			},
		},
	}

	for _, tc := range testcases {

		t.Run(tc.name, func(t *testing.T) {
			err = serverTest.BeforeEach()
			if err != nil {
				t.Fatalf("failed running 'BeforeEach' func in test case: %s", err)
			}

			caID, err := tc.before(caTest.Service)
			if err != nil {
				t.Fatalf("failed running 'before' func in test case: %s", err)
			}

			// Get the original CA before reissuance and capture the serial number
			var originalCA *models.CACertificate
			var originalSerialNumber string
			if caID != "" && caID != "non-existent-ca-id" {
				originalCA, _ = caTest.Service.GetCAByID(context.Background(), services.GetCAByIDInput{
					CAID: caID,
				})
				if originalCA != nil {
					originalSerialNumber = originalCA.Certificate.SerialNumber
				}
			}

			reissuedCA, err := tc.run(caTest.Service, caID)

			// Get fresh CA data after reissuance to see the actual updated state
			if reissuedCA != nil && err == nil {
				freshCA, _ := caTest.Service.GetCAByID(context.Background(), services.GetCAByIDInput{
					CAID: caID,
				})
				if freshCA != nil {
					reissuedCA = freshCA
				}
			}

			// Create a modified originalCA with the captured serial number for comparison
			if originalCA != nil {
				originalCAForComparison := *originalCA
				originalCAForComparison.Certificate.SerialNumber = originalSerialNumber
				originalCA = &originalCAForComparison
			}

			err = tc.resultCheck(caTest.Service, originalCA, reissuedCA, err)
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}
		})
	}
}

func TestReissueCASDK(t *testing.T) {
	serverTest, err := tests.TestServiceBuilder{}.WithDatabase("ca", "kms").Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	caTest := serverTest.CA

	var testcases = []struct {
		name        string
		before      func(caSDK services.CAService) (string, error)
		run         func(caSDK services.CAService, caID string) (*models.CACertificate, error)
		resultCheck func(caSDK services.CAService, originalCA *models.CACertificate, reissuedCA *models.CACertificate, err error) error
	}{
		{
			name: "OK/ReissueCA_ViaHTTPSDK",
			before: func(caSDK services.CAService) (string, error) {
				ca, err := createTestCA(caSDK, "SDK-Reissue-Test", false)
				if err != nil {
					return "", err
				}
				return ca.ID, nil
			},
			run: func(caSDK services.CAService, caID string) (*models.CACertificate, error) {
				return caSDK.ReissueCA(context.Background(), services.ReissueCAInput{
					CAID: caID,
				})
			},
			resultCheck: func(caSDK services.CAService, originalCA *models.CACertificate, reissuedCA *models.CACertificate, err error) error {
				if err != nil {
					return fmt.Errorf("unexpected error: %s", err)
				}

				// Basic verification
				if originalCA.ID != reissuedCA.ID {
					return fmt.Errorf("CA ID changed")
				}

				if originalCA.Certificate.SerialNumber == reissuedCA.Certificate.SerialNumber {
					return fmt.Errorf("serial number should have changed: both are %s", originalCA.Certificate.SerialNumber)
				}

				if reissuedCA.Certificate.Status != models.StatusActive {
					return fmt.Errorf("status is not ACTIVE")
				}

				return nil
			},
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			err = serverTest.BeforeEach()
			if err != nil {
				t.Fatalf("failed running 'BeforeEach' func in test case: %s", err)
			}

			caID, err := tc.before(caTest.Service)
			if err != nil {
				t.Fatalf("failed running 'before' func in test case: %s", err)
			}

			// Get the original CA before reissuance and capture the serial number
			originalCA, _ := caTest.HttpCASDK.GetCAByID(context.Background(), services.GetCAByIDInput{
				CAID: caID,
			})
			var originalSerialNumber string
			if originalCA != nil {
				originalSerialNumber = originalCA.Certificate.SerialNumber
			}

			reissuedCA, err := tc.run(caTest.HttpCASDK, caID)

			// Get fresh CA data after reissuance to see the actual updated state
			if reissuedCA != nil && err == nil {
				freshCA, _ := caTest.HttpCASDK.GetCAByID(context.Background(), services.GetCAByIDInput{
					CAID: caID,
				})
				if freshCA != nil {
					reissuedCA = freshCA
				}
			}

			// Create a modified originalCA with the captured serial number for comparison
			if originalCA != nil {
				originalCAForComparison := *originalCA
				originalCAForComparison.Certificate.SerialNumber = originalSerialNumber
				originalCA = &originalCAForComparison
			}

			err = tc.resultCheck(caTest.HttpCASDK, originalCA, reissuedCA, err)
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}
		})
	}
}

// Helper function to create a test CA
func createTestCA(caSDK services.CAService, commonName string, toExpire bool) (*models.CACertificate, error) {
	var caDur models.TimeDuration
	if toExpire {
		caDur = models.TimeDuration(time.Second) // 1 second
	} else {
		caDur = models.TimeDuration(time.Hour * 24 * 365) // 1 year
	}

	issuanceDur := models.TimeDuration(time.Hour * 24 * 180) // 6 months

	// Create issuance profile
	profile, err := caSDK.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
		Profile: models.IssuanceProfile{
			Validity: models.Validity{Type: models.Duration, Duration: issuanceDur},
		},
	})
	if err != nil {
		return nil, err
	}

	// Create CA
	ca, err := caSDK.CreateCA(context.Background(), services.CreateCAInput{
		KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
		Subject:      models.Subject{CommonName: commonName},
		CAExpiration: models.Validity{Type: models.Duration, Duration: caDur},
		ProfileID:    profile.ID,
	})
	if err != nil {
		return nil, err
	}

	return ca, nil
}

// Helper function to create a subordinate CA
func createSubordinateCA(caSDK services.CAService, parentCAID string, commonName string) (*models.CACertificate, error) {
	caDur := models.TimeDuration(time.Hour * 24 * 180)      // 6 months
	issuanceDur := models.TimeDuration(time.Hour * 24 * 90) // 3 months

	// Create issuance profile
	profile, err := caSDK.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
		Profile: models.IssuanceProfile{
			Validity: models.Validity{Type: models.Duration, Duration: issuanceDur},
		},
	})
	if err != nil {
		return nil, err
	}

	// Create subordinate CA
	ca, err := caSDK.CreateCA(context.Background(), services.CreateCAInput{
		ParentID:     parentCAID,
		KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
		Subject:      models.Subject{CommonName: commonName},
		CAExpiration: models.Validity{Type: models.Duration, Duration: caDur},
		ProfileID:    profile.ID,
	})
	if err != nil {
		return nil, err
	}

	return ca, nil
}
