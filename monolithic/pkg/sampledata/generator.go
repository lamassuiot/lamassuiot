package sampledata

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/sdk/v3"
	"github.com/sirupsen/logrus"
)

//go:embed ecdsa_p256_key.pem
var embeddedPrivateKey []byte

// PopulateSampleData populates the system with sample DMS, devices and issuance profiles for testing
// It uses HTTP clients to interact with the services
func PopulateSampleData(
	ctx context.Context,
	logger *logrus.Entry,
	caServiceURL string,
	deviceServiceURL string,
) error {
	logger.Info("Populating system with sample data...")

	// Setup HTTP client with insecure TLS (for development)
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	// Create CA SDK client
	caService := sdk.NewHttpCAClient(httpClient, caServiceURL)

	// Create DMS Manager SDK client - extract base URL from device service URL
	dmsServiceURL := extractBaseURL(deviceServiceURL)
	dmsService := sdk.NewHttpDMSManagerClient(httpClient, dmsServiceURL)

	// Step 1: Create Issuance Profiles for the CAs
	logger.Info("Creating CA issuance profiles...")

	caProfiles := []models.IssuanceProfile{
		{
			ID:          "profile-imported-root-ca",
			Name:        "Imported Root CA Profile",
			Description: "Profile for the imported root CA",
			Validity: models.Validity{
				Type:     models.Duration,
				Duration: models.TimeDuration(3650 * 24 * time.Hour), // 10 years
			},
			SignAsCA:               true,
			HonorKeyUsage:          true,
			HonorExtendedKeyUsages: true,
			HonorSubject:           true,
			Subject:                models.Subject{},
		},
		{
			ID:          "profile-generated-root-ca",
			Name:        "Generated Root CA Profile",
			Description: "Profile for the generated root CA",
			Validity: models.Validity{
				Type:     models.Duration,
				Duration: models.TimeDuration(3650 * 24 * time.Hour), // 10 years
			},
			SignAsCA:               true,
			HonorKeyUsage:          true,
			HonorExtendedKeyUsages: true,
			HonorSubject:           true,
			Subject:                models.Subject{},
		},
	}

	for _, profile := range caProfiles {
		logger.Infof("Creating CA issuance profile: %s", profile.ID)
		_, err := caService.CreateIssuanceProfile(ctx, services.CreateIssuanceProfileInput{
			Profile: profile,
		})
		if err != nil {
			logger.Warnf("Could not create CA issuance profile %s (may already exist): %v", profile.ID, err)
		} else {
			logger.Infof("Created CA issuance profile: %s", profile.ID)
		}
	}

	// Step 2: Import the Root CA using the embedded ECDSA key
	logger.Info("Importing Root CA from embedded ECDSA key...")

	importedCAID, err := importRootCA(ctx, logger, caService)
	if err != nil {
		logger.Warnf("Could not import root CA: %v", err)
	} else {
		logger.Infof("Successfully imported Root CA: %s", importedCAID)
	}

	// Step 3: Create a Generated Root CA
	logger.Info("Creating Generated Root CA...")

	generatedCAID := "sample-generated-root-ca"
	generatedCA, err := caService.CreateCA(ctx, services.CreateCAInput{
		ID: generatedCAID,
		Subject: models.Subject{
			CommonName:       "Sample Generated Root CA",
			Organization:     "LamassuIoT Sample",
			OrganizationUnit: "Development",
			Country:          "ES",
			State:            "Gipuzkoa",
			Locality:         "Arrasate",
		},
		KeyMetadata: models.KeyMetadata{
			Type: models.KeyType(x509.ECDSA),
			Bits: 256,
		},
		CAExpiration: models.Validity{
			Type:     models.Duration,
			Duration: models.TimeDuration(3650 * 24 * time.Hour), // 10 years
		},
		ProfileID: "profile-generated-root-ca",
		Metadata: map[string]any{
			"sample": true,
			"type":   "generated-root",
		},
	})
	if err != nil {
		logger.Warnf("Could not create generated root CA (may already exist): %v", err)
	} else {
		logger.Infof("Created Generated Root CA: %s", generatedCA.ID)
	}

	// Step 4: Issue certificates from both CAs
	if importedCAID != "" {
		logger.Infof("Issuing certificates from Imported Root CA: %s", importedCAID)
		err = issueSampleCertificates(ctx, logger, caService, importedCAID, "imported")
		if err != nil {
			logger.Warnf("Could not issue certificates from imported CA: %v", err)
		}
	}

	if generatedCA != nil {
		logger.Infof("Issuing certificates from Generated Root CA: %s", generatedCA.ID)
		err = issueSampleCertificates(ctx, logger, caService, generatedCA.ID, "generated")
		if err != nil {
			logger.Warnf("Could not issue certificates from generated CA: %v", err)
		}
	}

	// Create sample DMS first
	sampleDMSID := "sample-dms-01"
	logger.Infof("Creating sample DMS: %s", sampleDMSID)

	dmsInput := services.CreateDMSInput{
		ID:   sampleDMSID,
		Name: "Sample DMS",
		Metadata: map[string]interface{}{
			"description": "Sample DMS for testing",
			"sample":      true,
		},
		Settings: models.DMSSettings{
			EnrollmentSettings: models.EnrollmentSettings{
				EnrollmentProtocol: models.EST,
				EnrollmentCA:       "", // Will be set if needed
				DeviceProvisionProfile: models.DeviceProvisionProfile{
					Icon:      "Laptop",
					IconColor: "#0066CC",
					Metadata: map[string]interface{}{
						"sample": true,
					},
					Tags: []string{"sample", "test"},
				},
				RegistrationMode: models.JITP,
			},
			ReEnrollmentSettings: models.ReEnrollmentSettings{
				RevokeOnReEnrollment: false,
			},
			CADistributionSettings: models.CADistributionSettings{
				IncludeLamassuSystemCA: true,
			},
		},
	}

	createdDMS, err := dmsService.CreateDMS(ctx, dmsInput)
	if err != nil {
		logger.Warnf("Could not create DMS (may already exist): %v", err)
	} else {
		logger.Infof("Created sample DMS: %s", createdDMS.ID)
	}

	// Create sample devices with varied properties for device groups testing
	sampleDevices := []struct {
		id        string
		tags      []string
		icon      string
		iconColor string
		metadata  map[string]interface{}
	}{
		{
			id:        "device-001",
			tags:      []string{"production", "warehouse", "sensor"},
			icon:      "Thermometer",
			iconColor: "#FF6B6B",
			metadata: map[string]interface{}{
				"location":     "Warehouse A",
				"type":         "temperature-sensor",
				"manufacturer": "SensorCorp",
				"firmware":     "v2.1.0",
				"sample":       true,
			},
		},
		{
			id:        "device-002",
			tags:      []string{"production", "warehouse", "sensor"},
			icon:      "AirVent",
			iconColor: "#4ECDC4",
			metadata: map[string]interface{}{
				"location":     "Warehouse A",
				"type":         "humidity-sensor",
				"manufacturer": "SensorCorp",
				"firmware":     "v2.1.0",
				"sample":       true,
			},
		},
		{
			id:        "device-003",
			tags:      []string{"development", "lab", "gateway"},
			icon:      "Router",
			iconColor: "#95E1D3",
			metadata: map[string]interface{}{
				"location":     "Lab B",
				"type":         "iot-gateway",
				"manufacturer": "TechGateway",
				"firmware":     "v1.5.2",
				"sample":       true,
			},
		},
		{
			id:        "device-004",
			tags:      []string{"production", "field", "controller"},
			icon:      "Cpu",
			iconColor: "#F38181",
			metadata: map[string]interface{}{
				"location":     "Field Site C",
				"type":         "plc-controller",
				"manufacturer": "IndustrialSys",
				"firmware":     "v3.0.1",
				"sample":       true,
			},
		},
		{
			id:        "device-005",
			tags:      []string{"production", "field", "sensor"},
			icon:      "Gauge",
			iconColor: "#AA96DA",
			metadata: map[string]interface{}{
				"location":     "Field Site C",
				"type":         "pressure-sensor",
				"manufacturer": "SensorCorp",
				"firmware":     "v2.0.5",
				"sample":       true,
			},
		},
		{
			id:        "device-006",
			tags:      []string{"staging", "test", "actuator"},
			icon:      "Zap",
			iconColor: "#FCBAD3",
			metadata: map[string]interface{}{
				"location":     "Test Lab B",
				"type":         "electric-actuator",
				"manufacturer": "ActuatorTech",
				"firmware":     "v1.2.3",
				"sample":       true,
			},
		},
		{
			id:        "device-007",
			tags:      []string{"production", "warehouse", "camera"},
			icon:      "Camera",
			iconColor: "#A8D8EA",
			metadata: map[string]interface{}{
				"location":     "Warehouse A",
				"type":         "security-camera",
				"manufacturer": "VisionTech",
				"firmware":     "v4.2.1",
				"sample":       true,
			},
		},
		{
			id:        "device-008",
			tags:      []string{"development", "lab", "sensor"},
			icon:      "Activity",
			iconColor: "#FFD3B6",
			metadata: map[string]interface{}{
				"location":     "Lab B",
				"type":         "accelerometer",
				"manufacturer": "MotionSense",
				"firmware":     "v1.8.0",
				"sample":       true,
			},
		},
		{
			id:        "device-009",
			tags:      []string{"production", "field", "gateway"},
			icon:      "Radio",
			iconColor: "#FFAAA5",
			metadata: map[string]interface{}{
				"location":     "Field Site D",
				"type":         "edge-gateway",
				"manufacturer": "EdgeTech",
				"firmware":     "v2.3.4",
				"sample":       true,
			},
		},
		{
			id:        "device-010",
			tags:      []string{"staging", "test", "sensor"},
			icon:      "Fan",
			iconColor: "#FF8B94",
			metadata: map[string]interface{}{
				"location":     "Test Lab A",
				"type":         "airflow-sensor",
				"manufacturer": "EnvironmentSys",
				"firmware":     "v1.1.0",
				"sample":       true,
			},
		},
	}

	// Get device manager service URL
	deviceManagerService := sdk.NewHttpDeviceManagerClient(httpClient, deviceServiceURL)

	logger.Info("Creating sample devices...")
	var usedDMSID string
	if createdDMS != nil {
		usedDMSID = createdDMS.ID
	} else {
		usedDMSID = sampleDMSID
	}

	for _, device := range sampleDevices {
		logger.Infof("Creating sample device: %s", device.id)

		deviceInput := services.CreateDeviceInput{
			ID:        device.id,
			Tags:      device.tags,
			Icon:      device.icon,
			IconColor: device.iconColor,
			Metadata:  device.metadata,
			DMSID:     usedDMSID,
		}

		_, err := deviceManagerService.CreateDevice(ctx, deviceInput)
		if err != nil {
			logger.Warnf("Could not create device %s (may already exist): %v", device.id, err)
		} else {
			logger.Infof("Created sample device: %s", device.id)
		}
	}

	// Create some sample issuance profiles
	sampleProfiles := []models.IssuanceProfile{
		{
			ID:          "profile-server",
			Name:        "Server Certificates",
			Description: "Profile for issuing server certificates",
			Validity: models.Validity{
				Type:     models.Duration,
				Duration: models.TimeDuration(365 * 24 * time.Hour), // 365 days = 1 year
				Time:     time.Time{},
			},
			SignAsCA:               false,
			HonorKeyUsage:          true,
			HonorExtendedKeyUsages: true,
			HonorSubject:           true,
			Subject:                models.Subject{},
		},
		{
			ID:          "profile-client",
			Name:        "Client Certificates",
			Description: "Profile for issuing client certificates",
			Validity: models.Validity{
				Type:     models.Duration,
				Duration: models.TimeDuration(365 * 24 * time.Hour), // 365 days = 1 year
				Time:     time.Time{},
			},
			SignAsCA:               false,
			HonorKeyUsage:          true,
			HonorExtendedKeyUsages: true,
			HonorSubject:           true,
			Subject:                models.Subject{},
		},
		{
			ID:          "profile-device",
			Name:        "Device Certificates",
			Description: "Profile for issuing device certificates",
			Validity: models.Validity{
				Type:     models.Duration,
				Duration: models.TimeDuration(365 * 24 * time.Hour), // 365 days = 1 year
				Time:     time.Time{},
			},
			SignAsCA:               false,
			HonorKeyUsage:          true,
			HonorExtendedKeyUsages: true,
			HonorSubject:           true,
			Subject:                models.Subject{},
		},
	}

	logger.Info("Creating sample issuance profiles...")
	for _, profile := range sampleProfiles {
		logger.Infof("Creating sample issuance profile: %s", profile.ID)

		_, err := caService.CreateIssuanceProfile(ctx, services.CreateIssuanceProfileInput{
			Profile: profile,
		})
		if err != nil {
			// If profile already exists, that's okay for idempotency
			logger.Warnf("Could not create issuance profile %s (may already exist): %v", profile.ID, err)
		} else {
			logger.Infof("Created sample issuance profile: %s", profile.ID)
		}
	}

	logger.Info("Sample data population completed")
	return nil
}

// extractBaseURL extracts the base URL without the path
// converts "http://127.0.0.1:8080/api/devmanager" to "http://127.0.0.1:8080/api/dmsmanager"
func extractBaseURL(serviceURL string) string {
	// Simple extraction: replace /devmanager with /dmsmanager
	// This assumes the gateway URL structure
	return strings.ReplaceAll(serviceURL, "/api/devmanager", "/api/dmsmanager")
}

// parseURL parses a service URL into HTTPConnection config
func parseURL(serviceURL string) cconfig.HTTPConnection {
	// Simple parser - assumes format like "http://127.0.0.1:8080" or "https://127.0.0.1:8443"
	return cconfig.HTTPConnection{
		BasicConnection: cconfig.BasicConnection{
			Hostname: "127.0.0.1",
			Port:     0,
		},
		Protocol: cconfig.HTTP,
		BasePath: "",
	}
}

// importRootCA imports a root CA using the embedded ECDSA private key
func importRootCA(ctx context.Context, logger *logrus.Entry, caService services.CAService) (string, error) {
	// Parse the embedded private key
	block, _ := pem.Decode(embeddedPrivateKey)
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM block containing private key")
	}

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse EC private key: %w", err)
	}

	// Generate a self-signed certificate using the private key
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         "Sample Imported Root CA",
			Organization:       []string{"LamassuIoT Sample"},
			OrganizationalUnit: []string{"Development"},
			Country:            []string{"ES"},
			Province:           []string{"Gipuzkoa"},
			Locality:           []string{"Arrasate"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(3650 * 24 * time.Hour), // 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
	}

	// Create self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return "", fmt.Errorf("failed to parse created certificate: %w", err)
	}

	// Convert to models.X509Certificate
	x509Cert := models.X509Certificate(*cert)

	// Import the CA
	caID := "sample-imported-root-ca"
	importedCA, err := caService.ImportCA(ctx, services.ImportCAInput{
		ID:            caID,
		CACertificate: &x509Cert,
		Key:           privateKey,
		EngineID:      "golang-1", // Use default software engine
		ProfileID:     "profile-imported-root-ca",
	})
	if err != nil {
		return "", fmt.Errorf("failed to import CA: %w", err)
	}

	return importedCA.ID, nil
}

// issueSampleCertificates issues a set of sample certificates from the specified CA
func issueSampleCertificates(ctx context.Context, logger *logrus.Entry, caService services.CAService, caID, caType string) error {
	// Define sample certificates to issue
	sampleCerts := []struct {
		commonName string
		dnsNames   []string
		certType   string
	}{
		{
			commonName: fmt.Sprintf("device-cert-%s-001", caType),
			dnsNames:   []string{fmt.Sprintf("device001.%s.example.com", caType)},
			certType:   "device",
		},
		{
			commonName: fmt.Sprintf("device-cert-%s-002", caType),
			dnsNames:   []string{fmt.Sprintf("device002.%s.example.com", caType)},
			certType:   "device",
		},
		{
			commonName: fmt.Sprintf("server-cert-%s", caType),
			dnsNames:   []string{fmt.Sprintf("api.%s.example.com", caType), fmt.Sprintf("www.%s.example.com", caType)},
			certType:   "server",
		},
		{
			commonName: fmt.Sprintf("client-cert-%s", caType),
			dnsNames:   []string{},
			certType:   "client",
		},
	}

	for _, certSpec := range sampleCerts {
		logger.Infof("Issuing certificate: %s from CA: %s", certSpec.commonName, caID)

		// Generate a private key for the certificate
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return fmt.Errorf("failed to generate private key for %s: %w", certSpec.commonName, err)
		}

		// Create a CSR
		csrTemplate := &x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName:   certSpec.commonName,
				Organization: []string{"LamassuIoT Sample"},
			},
			DNSNames: certSpec.dnsNames,
		}

		csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privKey)
		if err != nil {
			return fmt.Errorf("failed to create CSR for %s: %w", certSpec.commonName, err)
		}

		csr, err := x509.ParseCertificateRequest(csrDER)
		if err != nil {
			return fmt.Errorf("failed to parse CSR for %s: %w", certSpec.commonName, err)
		}

		// Convert to models.X509CertificateRequest
		x509CSR := models.X509CertificateRequest(*csr)

		// Determine which profile to use
		var profileID string
		switch certSpec.certType {
		case "device":
			profileID = "profile-device"
		case "server":
			profileID = "profile-server"
		case "client":
			profileID = "profile-client"
		default:
			profileID = "profile-device"
		}

		// Sign the certificate
		signedCert, err := caService.SignCertificate(ctx, services.SignCertificateInput{
			CAID:              caID,
			CertRequest:       &x509CSR,
			IssuanceProfileID: profileID,
		})
		if err != nil {
			logger.Warnf("Could not sign certificate %s (may have issues): %v", certSpec.commonName, err)
			continue
		}

		logger.Infof("Successfully issued certificate: %s (Serial: %s)", certSpec.commonName, signedCert.SerialNumber)
	}

	return nil
}
