package dmsmanager

import (
	"context"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	dmshelpers "github.com/lamassuiot/lamassuiot/backend/v3/pkg/helpers"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCMPE2EOpenSSLClient(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not available")
	}

	ctx := context.Background()
	dmsMgr, testServers, err := StartDMSManagerServiceTestServer(t, false)
	require.NoError(t, err)

	createCA := func(name string) *models.CACertificate {
		t.Helper()

		lifespan, err := models.ParseDuration("1y")
		require.NoError(t, err)
		issuance, err := models.ParseDuration("30d")
		require.NoError(t, err)

		profile, err := testServers.CA.Service.CreateIssuanceProfile(ctx, services.CreateIssuanceProfileInput{
			Profile: models.IssuanceProfile{
				Validity: models.Validity{Type: models.Duration, Duration: models.TimeDuration(issuance)},
			},
		})
		require.NoError(t, err)

		ca, err := testServers.CA.Service.CreateCA(ctx, services.CreateCAInput{
			KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.ECDSA), Bits: 256},
			Subject:      models.Subject{CommonName: name},
			CAExpiration: models.Validity{Type: models.Duration, Duration: models.TimeDuration(lifespan)},
			ProfileID:    profile.ID,
			Metadata:     map[string]any{},
		})
		require.NoError(t, err)

		return ca
	}

	enrollCA := createCA("cmp-enroll")

	dms, err := dmsMgr.Service.CreateDMS(ctx, services.CreateDMSInput{
		ID:   "cmp-e2e-dms",
		Name: "CMP E2E",
		Settings: models.DMSSettings{
			EnrollmentSettings: models.EnrollmentSettings{
				EnrollmentProtocol: models.CMP,
				EnrollmentCA:       enrollCA.ID,
				DeviceProvisionProfile: models.DeviceProvisionProfile{
					Icon:      "cmp",
					IconColor: "#004466",
					Metadata:  map[string]any{},
					Tags:      []string{"cmp", "e2e"},
				},
				RegistrationMode:            models.PreRegistration,
				EnableReplaceableEnrollment: true,
			},
			ReEnrollmentSettings: models.ReEnrollmentSettings{
				AdditionalValidationCAs:     []string{},
				ReEnrollmentDelta:           models.TimeDuration(time.Hour),
				EnableExpiredRenewal:        true,
				PreventiveReEnrollmentDelta: models.TimeDuration(3 * time.Minute),
				CriticalReEnrollmentDelta:   models.TimeDuration(2 * time.Minute),
			},
			CADistributionSettings: models.CADistributionSettings{
				IncludeLamassuSystemCA: true,
				IncludeEnrollmentCA:    true,
			},
		},
	})
	require.NoError(t, err)

	deviceID := "cmp-device-e2e"
	_, err = testServers.DeviceManager.Service.CreateDevice(ctx, services.CreateDeviceInput{
		ID:        deviceID,
		Alias:     deviceID,
		Tags:      []string{"cmp"},
		Metadata:  map[string]any{},
		DMSID:     dms.ID,
		Icon:      "cmp",
		IconColor: "#004466",
	})
	require.NoError(t, err)

	tmpDir := t.TempDir()

	signerKey, err := chelpers.GenerateECDSAKey(elliptic.P256())
	require.NoError(t, err)
	signerCert, err := chelpers.GenerateSelfSignedCertificate(signerKey, "cmp-signer")
	require.NoError(t, err)

	signerKeyPEM, err := chelpers.PrivateKeyToPEM(signerKey)
	require.NoError(t, err)
	signerKeyPath := filepath.Join(tmpDir, "signer.key")
	require.NoError(t, os.WriteFile(signerKeyPath, []byte(signerKeyPEM), 0o600))

	signerCertPath := filepath.Join(tmpDir, "signer.crt")
	require.NoError(t, os.WriteFile(signerCertPath, []byte(chelpers.CertificateToPEM(signerCert)), 0o600))

	protectionProvider, ok := dmsMgr.Service.(services.LightweightCMPProtectionProvider)
	require.True(t, ok, "dms manager service must provide cmp protection credentials")
	protectionCert, _, err := protectionProvider.LWCProtectionCredentials()
	require.NoError(t, err)
	protectionCertPath := filepath.Join(tmpDir, "cmp-protection.crt")
	require.NoError(t, os.WriteFile(protectionCertPath, []byte(chelpers.CertificateToPEM(protectionCert)), 0o600))

	deviceKey, err := chelpers.GenerateECDSAKey(elliptic.P256())
	require.NoError(t, err)
	deviceKeyPEM, err := chelpers.PrivateKeyToPEM(deviceKey)
	require.NoError(t, err)
	deviceKeyPath := filepath.Join(tmpDir, "device.key")
	require.NoError(t, os.WriteFile(deviceKeyPath, []byte(deviceKeyPEM), 0o600))

	deviceCSR, err := chelpers.GenerateCertificateRequest(models.Subject{CommonName: deviceID}, deviceKey)
	require.NoError(t, err)
	deviceCSRPath := filepath.Join(tmpDir, "device.csr")
	require.NoError(t, os.WriteFile(deviceCSRPath, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: deviceCSR.Raw,
	}), 0o600))

	certOutPath := filepath.Join(tmpDir, "issued.crt")
	reqOutPath := filepath.Join(tmpDir, "request.der")
	rspOutPath := filepath.Join(tmpDir, "response.der")

	cmd := exec.CommandContext(ctx, "openssl", "cmp",
		"-server", fmt.Sprintf("https://127.0.0.1:%d", dmsMgr.Port),
		"-path", "/.well-known/cmp/p/"+dms.ID,
		"-cmd", "ir",
		"-cert", signerCertPath,
		"-key", signerKeyPath,
		"-csr", deviceCSRPath,
		"-newkey", deviceKeyPath,
		"-reqout", reqOutPath,
		"-rspout", rspOutPath,
		"-certout", certOutPath,
		"-ignore_keyusage",
		"-srvcert", protectionCertPath,
		"-verbosity", "8",
		"-batch",
	)
	output, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "openssl cmp failed:\n%s", string(output))

	fmt.Println(string(output))

	// Decode the raw CMP response PKIMessage using openssl asn1parse.
	if rspData, readErr := os.ReadFile(rspOutPath); readErr == nil {
		t.Logf("CMP response size: %d bytes", len(rspData))
		decodeCmd := exec.CommandContext(ctx, "openssl", "asn1parse", "-inform", "DER", "-in", rspOutPath)
		decodeOut, decodeErr := decodeCmd.CombinedOutput()
		if decodeErr != nil {
			t.Logf("openssl asn1parse (response) error: %v\n%s", decodeErr, string(decodeOut))
		} else {
			fmt.Println("=== CMP Response (PKIMessage) ASN.1 ===")
			fmt.Println(string(decodeOut))
		}
	}

	issuedCert, err := chelpers.ReadCertificateFromFile(certOutPath)

	// Decode the issued certificate using openssl x509.
	if err == nil {
		certPEM := chelpers.CertificateToPEM(issuedCert)
		certPEMPath := filepath.Join(tmpDir, "issued_check.pem")
		if writeErr := os.WriteFile(certPEMPath, []byte(certPEM), 0o600); writeErr == nil {
			certCmd := exec.CommandContext(ctx, "openssl", "x509", "-in", certPEMPath, "-text", "-noout")
			certOut, certErr := certCmd.CombinedOutput()
			if certErr != nil {
				t.Logf("openssl x509 error: %v\n%s", certErr, string(certOut))
			} else {
				fmt.Println("=== Issued Certificate ===")
				fmt.Println(string(certOut))
			}
		}
	}

	fmt.Println(issuedCert)

	require.NoError(t, err)
	assert.Equal(t, deviceID, issuedCert.Subject.CommonName)
	assert.NoError(t, dmshelpers.ValidateCertificate((*x509.Certificate)(enrollCA.Certificate.Certificate), issuedCert, true))

	device, err := testServers.DeviceManager.Service.GetDeviceByID(ctx, services.GetDeviceByIDInput{ID: deviceID})
	require.NoError(t, err)
	require.NotNil(t, device.IdentitySlot)

	serial := device.IdentitySlot.Secrets[device.IdentitySlot.ActiveVersion]
	storedCert, err := testServers.CA.Service.GetCertificateBySerialNumber(ctx, services.GetCertificatesBySerialNumberInput{
		SerialNumber: serial,
	})
	require.NoError(t, err)
	assert.Equal(t, issuedCert.Raw, []byte(storedCert.Certificate.Raw))

	valid, err := chelpers.ValidateCertAndPrivKey(issuedCert, nil, deviceKey)
	require.NoError(t, err)
	assert.True(t, valid)
}
