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

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/assemblers/tests"
	dmshelpers "github.com/lamassuiot/lamassuiot/backend/v3/pkg/helpers"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Shared fixture
// ---------------------------------------------------------------------------

// cmpTestFixture holds infrastructure shared across sub-tests.
type cmpTestFixture struct {
	ctx         context.Context
	dmsMgr      *tests.DMSManagerTestServer
	testServers *tests.TestServer
	enrollCA    *models.CACertificate
}

func newCMPTestFixture(t *testing.T) *cmpTestFixture {
	t.Helper()

	ctx := context.Background()
	dmsMgr, testServers, err := StartDMSManagerServiceTestServer(t, false)
	require.NoError(t, err)

	return &cmpTestFixture{
		ctx:         ctx,
		dmsMgr:      dmsMgr,
		testServers: testServers,
		enrollCA:    cmpCreateCA(t, ctx, testServers, "cmp-enroll"),
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func cmpCreateCA(t *testing.T, ctx context.Context, ts *tests.TestServer, name string) *models.CACertificate {
	t.Helper()

	lifespan, err := models.ParseDuration("1y")
	require.NoError(t, err)
	issuance, err := models.ParseDuration("30d")
	require.NoError(t, err)

	profile, err := ts.CA.Service.CreateIssuanceProfile(ctx, services.CreateIssuanceProfileInput{
		Profile: models.IssuanceProfile{
			Validity: models.Validity{Type: models.Duration, Duration: models.TimeDuration(issuance)},
		},
	})
	require.NoError(t, err)

	ca, err := ts.CA.Service.CreateCA(ctx, services.CreateCAInput{
		KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.ECDSA), Bits: 256},
		Subject:      models.Subject{CommonName: name},
		CAExpiration: models.Validity{Type: models.Duration, Duration: models.TimeDuration(lifespan)},
		ProfileID:    profile.ID,
		Metadata:     map[string]any{},
	})
	require.NoError(t, err)

	return ca
}

// cmpCreateProtectionCert creates a KMS-backed end-entity cert for signing CMP responses.
func cmpCreateProtectionCert(t *testing.T, ctx context.Context, ts *tests.TestServer) *models.Certificate {
	t.Helper()

	ca := cmpCreateCA(t, ctx, ts, "cmp-protection")

	cert, err := ts.CA.Service.CreateCertificate(ctx, services.CreateCertificateInput{
		CAID:     ca.ID,
		KeySpec:  services.CertificateKeySpec{Type: models.KeyType(x509.ECDSA), Bits: 256},
		Subject:  models.Subject{CommonName: "cmp-protection-cert"},
		Metadata: map[string]any{},
	})
	require.NoError(t, err)

	return cert
}

// cmpIssueSigner provisions a bootstrap CA in Lamassu and issues an EE
// certificate from it for the device to use as the CMP signer (extraCerts[0]).
// The bootstrap CA's ID is returned so the test can wire it into the DMS
// AuthOptionsMTLS.ValidationCAs list and exercise the real trust path.
func cmpIssueSigner(t *testing.T, ctx context.Context, ts *tests.TestServer, dir, signerCN string) (keyPath, certPath, bootstrapCAID string) {
	t.Helper()

	bootstrapCA := cmpCreateCA(t, ctx, ts, "cmp-bootstrap-"+signerCN)

	key, err := chelpers.GenerateECDSAKey(elliptic.P256())
	require.NoError(t, err)
	csr, err := chelpers.GenerateCertificateRequest(models.Subject{CommonName: signerCN}, key)
	require.NoError(t, err)

	issued, err := ts.CA.Service.SignCertificate(ctx, services.SignCertificateInput{
		CAID:              bootstrapCA.ID,
		CertRequest:       (*models.X509CertificateRequest)(csr),
		IssuanceProfileID: bootstrapCA.ProfileID,
	})
	require.NoError(t, err)

	keyPEM, err := chelpers.PrivateKeyToPEM(key)
	require.NoError(t, err)

	keyPath = filepath.Join(dir, "signer.key")
	certPath = filepath.Join(dir, "signer.crt")
	require.NoError(t, os.WriteFile(keyPath, []byte(keyPEM), 0o600))
	require.NoError(t, os.WriteFile(certPath, []byte(chelpers.CertificateToPEM((*x509.Certificate)(issued.Certificate))), 0o600))
	return keyPath, certPath, bootstrapCA.ID
}

func cmpCreateDMS(t *testing.T, ctx context.Context, dmsMgr *tests.DMSManagerTestServer, id, enrollCAID string, lwcOpts models.EnrollmentOptionsLWCRFC9483) *models.DMS {
	t.Helper()

	dms, err := dmsMgr.Service.CreateDMS(ctx, services.CreateDMSInput{
		ID:   id,
		Name: "CMP E2E " + id,
		Settings: models.DMSSettings{
			EnrollmentSettings: models.EnrollmentSettings{
				EnrollmentProtocol: models.CMP,
				EnrollmentCA:       enrollCAID,
				DeviceProvisionProfile: models.DeviceProvisionProfile{
					Icon:      "cmp",
					IconColor: "#004466",
					Metadata:  map[string]any{},
					Tags:      []string{"cmp", "e2e"},
				},
				RegistrationMode:            models.PreRegistration,
				EnableReplaceableEnrollment: true,
				EnrollmentOptionsLWCRFC9483: lwcOpts,
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

	return dms
}

func cmpPreRegisterDevice(t *testing.T, ctx context.Context, ts *tests.TestServer, deviceID, dmsID string) {
	t.Helper()

	_, err := ts.DeviceManager.Service.CreateDevice(ctx, services.CreateDeviceInput{
		ID:        deviceID,
		Alias:     deviceID,
		Tags:      []string{"cmp"},
		Metadata:  map[string]any{},
		DMSID:     dmsID,
		Icon:      "cmp",
		IconColor: "#004466",
	})
	require.NoError(t, err)
}

// cmpWriteDeviceFiles writes a fresh device key+CSR to dir.
func cmpWriteDeviceFiles(t *testing.T, dir, deviceID string) (keyPath, csrPath string) {
	t.Helper()

	key, err := chelpers.GenerateECDSAKey(elliptic.P256())
	require.NoError(t, err)
	keyPEM, err := chelpers.PrivateKeyToPEM(key)
	require.NoError(t, err)
	csr, err := chelpers.GenerateCertificateRequest(models.Subject{CommonName: deviceID}, key)
	require.NoError(t, err)

	keyPath = filepath.Join(dir, "device.key")
	csrPath = filepath.Join(dir, "device.csr")
	require.NoError(t, os.WriteFile(keyPath, []byte(keyPEM), 0o600))
	require.NoError(t, os.WriteFile(csrPath, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr.Raw,
	}), 0o600))
	return keyPath, csrPath
}

// cmpRunEnroll runs `openssl cmp -cmd ir` with a 15-second hard deadline so the
// process cannot hang indefinitely in failure scenarios.
// srvcertPath may be empty to omit -srvcert.
func cmpRunEnroll(ctx context.Context, serverAddr, dmsID, signerKey, signerCert, deviceKey, deviceCSR, srvcertPath, certOut, dir string) ([]byte, error) {
	cmdCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	args := []string{
		"cmp",
		"-server", serverAddr,
		"-path", "/.well-known/cmp/p/" + dmsID,
		"-cmd", "ir",
		"-cert", signerCert,
		"-key", signerKey,
		"-extracerts", signerCert, // include signer cert in extraCerts so server can verify signature
		"-csr", deviceCSR,
		"-newkey", deviceKey,
		"-reqout", filepath.Join(dir, "request.der"),
		"-rspout", filepath.Join(dir, "response.der"),
		"-certout", certOut,
		"-ignore_keyusage",
		"-verbosity", "8",
		"-batch",
	}

	if srvcertPath != "" {
		args = append(args, "-srvcert", srvcertPath)
	} else {
		// No server cert pinning: send the request but accept any (or no) protection.
		args = append(args, "-unprotected_errors")
	}

	return exec.CommandContext(cmdCtx, "openssl", args...).CombinedOutput()
}

// cmpLogDiagnostics prints the raw CMP response and issued cert (best-effort, never fatal).
func cmpLogDiagnostics(t *testing.T, ctx context.Context, dir, certOut string) {
	t.Helper()

	diagCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	rspPath := filepath.Join(dir, "response.der")
	if data, err := os.ReadFile(rspPath); err == nil {
		t.Logf("CMP response size: %d bytes", len(data))
		if out, err := exec.CommandContext(diagCtx, "openssl", "asn1parse", "-inform", "DER", "-in", rspPath).CombinedOutput(); err != nil {
			t.Logf("asn1parse error: %v\n%s", err, out)
		} else {
			t.Logf("=== CMP Response ASN.1 ===\n%s", out)
		}
	}

	cert, err := chelpers.ReadCertificateFromFile(certOut)
	if err != nil {
		return
	}
	pemPath := filepath.Join(dir, "issued_check.pem")
	if err := os.WriteFile(pemPath, []byte(chelpers.CertificateToPEM(cert)), 0o600); err != nil {
		return
	}
	if out, err := exec.CommandContext(diagCtx, "openssl", "x509", "-in", pemPath, "-text", "-noout").CombinedOutput(); err != nil {
		t.Logf("x509 error: %v\n%s", err, out)
	} else {
		t.Logf("=== Issued Certificate ===\n%s", out)
	}
}

// cmpAssertEnrolled verifies the cert was issued by the enroll CA and stored in the device slot.
func cmpAssertEnrolled(t *testing.T, ctx context.Context, ts *tests.TestServer, enrollCA *models.CACertificate, deviceID, certOut string) {
	t.Helper()

	issuedCert, err := chelpers.ReadCertificateFromFile(certOut)
	require.NoError(t, err)

	assert.Equal(t, deviceID, issuedCert.Subject.CommonName)
	assert.NoError(t, dmshelpers.ValidateCertificate((*x509.Certificate)(enrollCA.Certificate.Certificate), issuedCert, true))

	device, err := ts.DeviceManager.Service.GetDeviceByID(ctx, services.GetDeviceByIDInput{ID: deviceID})
	require.NoError(t, err)
	require.NotNil(t, device.IdentitySlot)

	serial := device.IdentitySlot.Secrets[device.IdentitySlot.ActiveVersion]
	stored, err := ts.CA.Service.GetCertificateBySerialNumber(ctx, services.GetCertificatesBySerialNumberInput{
		SerialNumber: serial,
	})
	require.NoError(t, err)
	assert.Equal(t, issuedCert.Raw, []byte(stored.Certificate.Raw))
}

// ---------------------------------------------------------------------------
// Table-driven test
// ---------------------------------------------------------------------------

func TestCMPE2EOpenSSLClient(t *testing.T) {
	// buildSerial is called BEFORE the DMS is created and returns the
	// ProtectionCertificateSerialNumber to embed in the DMS config ("" = no protection).
	//
	// buildSrvcert is called AFTER the DMS is created and returns the path to write
	// to the openssl -srvcert flag ("" = omit the flag).
	//
	// Separating the two phases lets buildSrvcert use the DMS ID (e.g. to call
	// LWCProtectionCredentials) while buildSerial can create the underlying cert first.
	type tc struct {
		name          string
		buildSerial   func(t *testing.T, f *cmpTestFixture) string
		buildSrvcert  func(t *testing.T, f *cmpTestFixture, dir, dmsID string) string
		expectSuccess bool
	}

	testcases := []tc{
		// Server is configured with a KMS-backed cert; client pins the exact same cert.
		// Enrollment must succeed and the certificate must be stored in the device slot.
		func() tc {
			// Shared between buildSerial and buildSrvcert via closure.
			var protSerial string
			return tc{
				name: "TrustedProtectionCert",
				buildSerial: func(t *testing.T, f *cmpTestFixture) string {
					protSerial = cmpCreateProtectionCert(t, f.ctx, f.testServers).SerialNumber
					return protSerial
				},
				buildSrvcert: func(t *testing.T, f *cmpTestFixture, dir, dmsID string) string {
					// LWCProtectionCredentials resolves the cert via the DMS config,
					// which was populated with protSerial above.
					provider, ok := f.dmsMgr.Service.(services.LightweightCMPProtectionProvider)
					require.True(t, ok, "service must implement LightweightCMPProtectionProvider")
					chain, _, err := provider.LWCProtectionCredentials(f.ctx, dmsID)
					require.NoError(t, err)

					path := filepath.Join(dir, "protection.crt")
					require.NoError(t, os.WriteFile(path, []byte(chelpers.CertificateToPEM(chain[0])), 0o600))
					return path
				},
				expectSuccess: true,
			}
		}(),

		// Server is configured with a real KMS-backed cert, but the client pins a
		// completely different self-signed cert.  The client must reject the response.
		func() tc {
			return tc{
				name: "UnknownProtectionCert",
				buildSerial: func(t *testing.T, f *cmpTestFixture) string {
					return cmpCreateProtectionCert(t, f.ctx, f.testServers).SerialNumber
				},
				buildSrvcert: func(t *testing.T, f *cmpTestFixture, dir, _ string) string {
					key, err := chelpers.GenerateECDSAKey(elliptic.P256())
					require.NoError(t, err)
					cert, err := chelpers.GenerateSelfSignedCertificate(key, "unknown-protection")
					require.NoError(t, err)

					path := filepath.Join(dir, "unknown-protection.crt")
					require.NoError(t, os.WriteFile(path, []byte(chelpers.CertificateToPEM(cert)), 0o600))
					return path
				},
				expectSuccess: false,
			}
		}(),

		// DMS has no protection cert configured → server sends unprotected responses.
		// openssl will reject an unprotected response when it expected protection.
		{
			name: "NoProtectionCert",
			buildSerial: func(_ *testing.T, _ *cmpTestFixture) string {
				return "" // no protection cert
			},
			buildSrvcert: func(_ *testing.T, _ *cmpTestFixture, _, _ string) string {
				return "" // omit -srvcert
			},
			expectSuccess: false,
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			f := newCMPTestFixture(t)
			dir := t.TempDir()

			serial := tc.buildSerial(t, f)

			// Provision a real bootstrap CA + signer cert so the DMS can
			// configure ValidationCAs and the server-side signer-cert chain
			// validation passes for the success case. Both protection-failure
			// subcases also need this — without a chain-valid signer the
			// server now rejects IR before any response-side handling, and
			// the failure surface we want to assert is openssl's response
			// validation, not server-side auth.
			signerKey, signerCert, bootstrapCAID := cmpIssueSigner(t, f.ctx, f.testServers, dir, fmt.Sprintf("signer-%s", tc.name))

			dms := cmpCreateDMS(t, f.ctx, f.dmsMgr,
				fmt.Sprintf("cmp-dms-%s", tc.name),
				f.enrollCA.ID,
				models.EnrollmentOptionsLWCRFC9483{
					AuthMode:                          models.CMPAuthModeClientCertificate,
					ProtectionCertificateSerialNumber: serial,
					AuthOptionsMTLS: models.AuthOptionsClientCertificate{
						ValidationCAs: []string{bootstrapCAID},
					},
				},
			)

			srvcertPath := tc.buildSrvcert(t, f, dir, dms.ID)

			deviceID := fmt.Sprintf("device-%s", tc.name)
			cmpPreRegisterDevice(t, f.ctx, f.testServers, deviceID, dms.ID)

			deviceKey, deviceCSR := cmpWriteDeviceFiles(t, dir, deviceID)
			certOut := filepath.Join(dir, "issued.crt")

			serverAddr := fmt.Sprintf("https://127.0.0.1:%d", f.dmsMgr.Port)
			output, err := cmpRunEnroll(f.ctx, serverAddr, dms.ID,
				signerKey, signerCert, deviceKey, deviceCSR,
				srvcertPath, certOut, dir)

			t.Logf("openssl output:\n%s", output)

			if tc.expectSuccess {
				require.NoErrorf(t, err, "openssl cmp should have succeeded")
				cmpLogDiagnostics(t, f.ctx, dir, certOut)
				cmpAssertEnrolled(t, f.ctx, f.testServers, f.enrollCA, deviceID, certOut)
			} else {
				assert.Error(t, err, "openssl cmp should have failed")
			}
		})
	}
}

// TestCMPE2ERevokedDeviceCert verifies that a re-enrollment (KUR) is rejected when
// the device's current certificate has been revoked.
//
// Flow:
//  1. Enroll a device (IR) → issued cert stored in device slot.
//  2. Revoke that cert via UpdateCertificateStatus.
//  3. Attempt KUR using the revoked cert as client protection → server rejects.
func TestCMPE2ERevokedDeviceCert(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not available")
	}

	f := newCMPTestFixture(t)
	dir := t.TempDir()

	// Provision a real bootstrap CA + signer cert. The bootstrap CA is wired
	// into AuthOptionsMTLS.ValidationCAs so the server-side signer-cert chain
	// validation passes for the initial IR — the KUR side then trusts the
	// device's previously-issued cert via the enrollment CA, mirroring the
	// EST reenrollment trust model.
	signerKey, signerCert, bootstrapCAID := cmpIssueSigner(t, f.ctx, f.testServers, dir, "signer-revoked-client")

	// Build DMS with a KMS-backed protection cert so the server signs responses.
	protCert := cmpCreateProtectionCert(t, f.ctx, f.testServers)
	dms := cmpCreateDMS(t, f.ctx, f.dmsMgr, "cmp-dms-revoked-client", f.enrollCA.ID,
		models.EnrollmentOptionsLWCRFC9483{
			AuthMode:                          models.CMPAuthModeClientCertificate,
			ProtectionCertificateSerialNumber: protCert.SerialNumber,
			AuthOptionsMTLS: models.AuthOptionsClientCertificate{
				ValidationCAs: []string{bootstrapCAID},
			},
		},
	)

	// Obtain the protection cert so openssl can pin it.
	provider, ok := f.dmsMgr.Service.(services.LightweightCMPProtectionProvider)
	require.True(t, ok)
	chain2, _, err := provider.LWCProtectionCredentials(f.ctx, dms.ID)
	require.NoError(t, err)
	srvcertPath := filepath.Join(dir, "protection.crt")
	require.NoError(t, os.WriteFile(srvcertPath, []byte(chelpers.CertificateToPEM(chain2[0])), 0o600))

	deviceID := "cmp-device-revoked-client"
	cmpPreRegisterDevice(t, f.ctx, f.testServers, deviceID, dms.ID)

	// Step 1: initial enrollment (IR).
	deviceKey, deviceCSR := cmpWriteDeviceFiles(t, dir, deviceID)
	certOut := filepath.Join(dir, "issued.crt")

	serverAddr := fmt.Sprintf("https://127.0.0.1:%d", f.dmsMgr.Port)
	output, err := cmpRunEnroll(f.ctx, serverAddr, dms.ID,
		signerKey, signerCert, deviceKey, deviceCSR,
		srvcertPath, certOut, dir)
	require.NoErrorf(t, err, "initial enrollment should succeed:\n%s", output)

	issuedCert, err := chelpers.ReadCertificateFromFile(certOut)
	require.NoError(t, err)

	// Step 2: revoke the issued device cert. Lamassu indexes certificates by
	// the lowercase hex serial number, not the big.Int decimal string, so we
	// convert via the shared helper to match how the service stores it.
	_, err = f.testServers.CA.Service.UpdateCertificateStatus(f.ctx, services.UpdateCertificateStatusInput{
		SerialNumber:     dmshelpers.SerialNumberToHexString(issuedCert.SerialNumber),
		NewStatus:        models.StatusRevoked,
		RevocationReason: models.RevocationReason(1), // KeyCompromise
	})
	require.NoError(t, err, "revoke device cert")

	// Step 3: attempt KUR with the revoked cert as client protection.
	// openssl uses the existing cert+key to authenticate the KUR request.
	// LWCReenroll checks the device slot, finds the cert is revoked, and rejects.
	kurOut := filepath.Join(dir, "renewed.crt")
	kurOutput, kurErr := cmpRunKUR(f.ctx, serverAddr, dms.ID,
		certOut, deviceKey, srvcertPath, kurOut, dir)
	t.Logf("openssl kur output:\n%s", kurOutput)

	assert.Error(t, kurErr, "KUR with a revoked device cert should be rejected")
}

// cmpRunKUR runs `openssl cmp -cmd kur` using an existing cert+key pair as client
// authentication. A 15-second deadline prevents the process from hanging.
func cmpRunKUR(ctx context.Context, serverAddr, dmsID, existingCertPath, existingKeyPath, srvcertPath, certOut, dir string) ([]byte, error) {
	cmdCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	args := []string{
		"cmp",
		"-server", serverAddr,
		"-path", "/.well-known/cmp/p/" + dmsID,
		"-cmd", "kur",
		"-cert", existingCertPath,
		"-key", existingKeyPath,
		"-reqout", filepath.Join(dir, "kur_request.der"),
		"-rspout", filepath.Join(dir, "kur_response.der"),
		"-certout", certOut,
		"-ignore_keyusage",
		"-srvcert", srvcertPath,
		"-verbosity", "8",
		"-batch",
	}

	return exec.CommandContext(cmdCtx, "openssl", args...).CombinedOutput()
}
