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

	// Create KMS SDK client - extract base URL from CA service URL
	kmsServiceURL := strings.ReplaceAll(caServiceURL, "/api/ca", "/api/kms")
	kmsService := sdk.NewHttpKMSClient(httpClient, kmsServiceURL)

	// Create DMS Manager SDK client - extract base URL from device service URL
	dmsServiceURL := extractBaseURL(deviceServiceURL)
	dmsService := sdk.NewHttpDMSManagerClient(httpClient, dmsServiceURL)

	// Step 1: Create Issuance Profiles for the CAs
	logger.Info("Creating CA issuance profiles...")

	// Create imported root CA profile
	importedRootCAProfile, err := caService.CreateIssuanceProfile(ctx, services.CreateIssuanceProfileInput{
		Profile: models.IssuanceProfile{
			Name:        "Imported Root CA Profile",
			Description: "Profile for the imported root CA",
			Validity: models.Validity{
				Type:     models.Duration,
				Duration: models.TimeDuration(3650 * 24 * time.Hour), // 10 years
			},
			SignAsCA:      true,
			HonorKeyUsage: false,
			KeyUsage: models.X509KeyUsage(
				x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
			),
			HonorExtendedKeyUsages: false,
			ExtendedKeyUsages:      []models.X509ExtKeyUsage{},
			HonorSubject:           true,
			Subject:                models.Subject{},
		},
	})
	if err != nil {
		logger.Warnf("Could not create imported root CA profile: %v", err)
		return err
	}
	logger.Infof("Created CA issuance profile: %s (ID: %s)", importedRootCAProfile.Name, importedRootCAProfile.ID)

	// Create generated root CA profile
	generatedRootCAProfile, err := caService.CreateIssuanceProfile(ctx, services.CreateIssuanceProfileInput{
		Profile: models.IssuanceProfile{
			Name:        "Generated Root CA Profile",
			Description: "Profile for the generated root CA",
			Validity: models.Validity{
				Type:     models.Duration,
				Duration: models.TimeDuration(3650 * 24 * time.Hour), // 10 years
			},
			SignAsCA:      true,
			HonorKeyUsage: false,
			KeyUsage: models.X509KeyUsage(
				x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
			),
			HonorExtendedKeyUsages: false,
			ExtendedKeyUsages:      []models.X509ExtKeyUsage{},
			HonorSubject:           true,
			Subject:                models.Subject{},
		},
	})
	if err != nil {
		logger.Warnf("Could not create generated root CA profile: %v", err)
		return err
	}
	logger.Infof("Created CA issuance profile: %s (ID: %s)", generatedRootCAProfile.Name, generatedRootCAProfile.ID)

	// Step 2: Import the private key into KMS and create CA using the imported key
	logger.Info("Importing private key into KMS and creating Root CA...")

	importedCAID, err := importKeyAndCreateCA(ctx, logger, kmsService, caService, importedRootCAProfile.ID)
	if err != nil {
		logger.Warnf("Could not import key and create root CA: %v", err)
	} else {
		logger.Infof("Successfully imported key and created Root CA: %s", importedCAID)
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
		ProfileID: generatedRootCAProfile.ID,
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
	// First create certificate issuance profiles
	logger.Info("Creating certificate issuance profiles...")

	// Create server profile
	serverProfile, err := caService.CreateIssuanceProfile(ctx, services.CreateIssuanceProfileInput{
		Profile: models.IssuanceProfile{
			Name:        "Server Certificates",
			Description: "Profile for issuing server certificates",
			Validity: models.Validity{
				Type:     models.Duration,
				Duration: models.TimeDuration(365 * 24 * time.Hour), // 365 days = 1 year
			},
			SignAsCA:      false,
			HonorKeyUsage: false,
			KeyUsage: models.X509KeyUsage(
				x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			),
			HonorExtendedKeyUsages: false,
			ExtendedKeyUsages: []models.X509ExtKeyUsage{
				models.X509ExtKeyUsage(x509.ExtKeyUsageServerAuth),
			},
			HonorSubject: true,
			Subject:      models.Subject{},
		},
	})
	if err != nil {
		logger.Warnf("Could not create server profile: %v", err)
	} else {
		logger.Infof("Created issuance profile: %s (ID: %s)", serverProfile.Name, serverProfile.ID)
	}

	// Create client profile
	clientProfile, err := caService.CreateIssuanceProfile(ctx, services.CreateIssuanceProfileInput{
		Profile: models.IssuanceProfile{
			Name:        "Client Certificates",
			Description: "Profile for issuing client certificates",
			Validity: models.Validity{
				Type:     models.Duration,
				Duration: models.TimeDuration(365 * 24 * time.Hour), // 365 days = 1 year
			},
			SignAsCA:      false,
			HonorKeyUsage: false,
			KeyUsage: models.X509KeyUsage(
				x509.KeyUsageDigitalSignature,
			),
			HonorExtendedKeyUsages: false,
			ExtendedKeyUsages: []models.X509ExtKeyUsage{
				models.X509ExtKeyUsage(x509.ExtKeyUsageClientAuth),
			},
			HonorSubject: true,
			Subject:      models.Subject{},
		},
	})
	if err != nil {
		logger.Warnf("Could not create client profile: %v", err)
	} else {
		logger.Infof("Created issuance profile: %s (ID: %s)", clientProfile.Name, clientProfile.ID)
	}

	// Create device profile
	deviceProfile, err := caService.CreateIssuanceProfile(ctx, services.CreateIssuanceProfileInput{
		Profile: models.IssuanceProfile{
			Name:        "Device Certificates",
			Description: "Profile for issuing device certificates",
			Validity: models.Validity{
				Type:     models.Duration,
				Duration: models.TimeDuration(365 * 24 * time.Hour), // 365 days = 1 year
			},
			SignAsCA:      false,
			HonorKeyUsage: false,
			KeyUsage: models.X509KeyUsage(
				x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			),
			HonorExtendedKeyUsages: false,
			ExtendedKeyUsages: []models.X509ExtKeyUsage{
				models.X509ExtKeyUsage(x509.ExtKeyUsageClientAuth),
				models.X509ExtKeyUsage(x509.ExtKeyUsageServerAuth),
			},
			HonorSubject: true,
			Subject:      models.Subject{},
		},
	})
	if err != nil {
		logger.Warnf("Could not create device profile: %v", err)
	} else {
		logger.Infof("Created issuance profile: %s (ID: %s)", deviceProfile.Name, deviceProfile.ID)
	}

	// Now issue certificates using the actual profile IDs
	if importedCAID != "" && serverProfile != nil && clientProfile != nil && deviceProfile != nil {
		logger.Infof("Issuing certificates from Imported Root CA: %s", importedCAID)
		err = issueSampleCertificates(ctx, logger, caService, importedCAID, "imported", map[string]string{
			"server": serverProfile.ID,
			"client": clientProfile.ID,
			"device": deviceProfile.ID,
		})
		if err != nil {
			logger.Warnf("Could not issue certificates from imported CA: %v", err)
		}
	}

	if generatedCA != nil && serverProfile != nil && clientProfile != nil && deviceProfile != nil {
		logger.Infof("Issuing certificates from Generated Root CA: %s", generatedCA.ID)
		err = issueSampleCertificates(ctx, logger, caService, generatedCA.ID, "generated", map[string]string{
			"server": serverProfile.ID,
			"client": clientProfile.ID,
			"device": deviceProfile.ID,
		})
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
				EnrollmentOptionsESTRFC7030: models.EnrollmentOptionsESTRFC7030{
					AuthMode: "CLIENT_CERTIFICATE",
					AuthOptionsMTLS: models.AuthOptionsClientCertificate{
						ValidationCAs:        []string{},
						ChainLevelValidation: -1,
						AllowExpired:         false,
					},
				},
				EnrollmentCA: importedCAID,
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
				RevokeOnReEnrollment:    false,
				AdditionalValidationCAs: []string{},
			},
			CADistributionSettings: models.CADistributionSettings{
				IncludeEnrollmentCA:    true,
				IncludeLamassuSystemCA: true,
				ManagedCAs:             []string{},
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
		{
			id:        "device-011",
			tags:      []string{"production", "warehouse", "sensor"},
			icon:      "Thermometer",
			iconColor: "#3498DB",
			metadata: map[string]interface{}{
				"location":     "Warehouse B",
				"type":         "water-level-sensor",
				"manufacturer": "FluidSense",
				"firmware":     "v1.9.2",
				"sample":       true,
			},
		},
		{
			id:        "device-012",
			tags:      []string{"production", "field", "sensor"},
			icon:      "AirVent",
			iconColor: "#1ABC9C",
			metadata: map[string]interface{}{
				"location":     "Field Site A",
				"type":         "wind-sensor",
				"manufacturer": "WeatherTech",
				"firmware":     "v2.5.0",
				"sample":       true,
			},
		},
		{
			id:        "device-013",
			tags:      []string{"development", "lab", "controller"},
			icon:      "Cpu",
			iconColor: "#9B59B6",
			metadata: map[string]interface{}{
				"location":     "Lab A",
				"type":         "micro-controller",
				"manufacturer": "EmbeddedSys",
				"firmware":     "v1.0.5",
				"sample":       true,
			},
		},
		{
			id:        "device-014",
			tags:      []string{"production", "warehouse", "actuator"},
			icon:      "Zap",
			iconColor: "#E74C3C",
			metadata: map[string]interface{}{
				"location":     "Warehouse B",
				"type":         "alarm-system",
				"manufacturer": "SecurityPro",
				"firmware":     "v3.2.1",
				"sample":       true,
			},
		},
		{
			id:        "device-015",
			tags:      []string{"staging", "warehouse", "sensor"},
			icon:      "Gauge",
			iconColor: "#F39C12",
			metadata: map[string]interface{}{
				"location":     "Warehouse C",
				"type":         "light-sensor",
				"manufacturer": "LuminaTech",
				"firmware":     "v1.7.3",
				"sample":       true,
			},
		},
		{
			id:        "device-016",
			tags:      []string{"production", "field", "gateway"},
			icon:      "Router",
			iconColor: "#16A085",
			metadata: map[string]interface{}{
				"location":     "Field Site B",
				"type":         "wireless-gateway",
				"manufacturer": "ConnectTech",
				"firmware":     "v2.8.1",
				"sample":       true,
			},
		},
		{
			id:        "device-017",
			tags:      []string{"development", "lab", "sensor"},
			icon:      "Activity",
			iconColor: "#34495E",
			metadata: map[string]interface{}{
				"location":     "Lab C",
				"type":         "rain-detector",
				"manufacturer": "WeatherSense",
				"firmware":     "v1.4.0",
				"sample":       true,
			},
		},
		{
			id:        "device-018",
			tags:      []string{"production", "warehouse", "controller"},
			icon:      "Cpu",
			iconColor: "#7F8C8D",
			metadata: map[string]interface{}{
				"location":     "Warehouse A",
				"type":         "hvac-controller",
				"manufacturer": "ClimateTech",
				"firmware":     "v4.1.2",
				"sample":       true,
			},
		},
		{
			id:        "device-019",
			tags:      []string{"staging", "test", "gateway"},
			icon:      "Radio",
			iconColor: "#2ECC71",
			metadata: map[string]interface{}{
				"location":     "Test Lab C",
				"type":         "mesh-gateway",
				"manufacturer": "MeshNet",
				"firmware":     "v2.0.0",
				"sample":       true,
			},
		},
		{
			id:        "device-020",
			tags:      []string{"production", "field", "sensor"},
			icon:      "Thermometer",
			iconColor: "#F1C40F",
			metadata: map[string]interface{}{
				"location":     "Field Site E",
				"type":         "solar-irradiance-sensor",
				"manufacturer": "SolarTech",
				"firmware":     "v1.6.4",
				"sample":       true,
			},
		},
		{
			id:        "device-021",
			tags:      []string{"production", "warehouse", "camera"},
			icon:      "Camera",
			iconColor: "#E67E22",
			metadata: map[string]interface{}{
				"location":     "Warehouse C",
				"type":         "video-recorder",
				"manufacturer": "VisionTech",
				"firmware":     "v5.0.1",
				"sample":       true,
			},
		},
		{
			id:        "device-022",
			tags:      []string{"development", "lab", "actuator"},
			icon:      "Zap",
			iconColor: "#C0392B",
			metadata: map[string]interface{}{
				"location":     "Lab D",
				"type":         "power-switch",
				"manufacturer": "ElectroSys",
				"firmware":     "v2.3.0",
				"sample":       true,
			},
		},
		{
			id:        "device-023",
			tags:      []string{"production", "field", "sensor"},
			icon:      "Gauge",
			iconColor: "#ECF0F1",
			metadata: map[string]interface{}{
				"location":     "Field Site F",
				"type":         "snow-depth-sensor",
				"manufacturer": "WeatherSense",
				"firmware":     "v1.3.1",
				"sample":       true,
			},
		},
		{
			id:        "device-024",
			tags:      []string{"staging", "warehouse", "controller"},
			icon:      "Cpu",
			iconColor: "#D35400",
			metadata: map[string]interface{}{
				"location":     "Warehouse D",
				"type":         "logistics-controller",
				"manufacturer": "LogisticsPro",
				"firmware":     "v3.5.2",
				"sample":       true,
			},
		},
		{
			id:        "device-025",
			tags:      []string{"production", "field", "gateway"},
			icon:      "Router",
			iconColor: "#2980B9",
			metadata: map[string]interface{}{
				"location":     "Field Site G",
				"type":         "ble-gateway",
				"manufacturer": "WirelessHub",
				"firmware":     "v1.8.5",
				"sample":       true,
			},
		},
		{
			id:        "device-026",
			tags:      []string{"development", "lab", "sensor"},
			icon:      "Activity",
			iconColor: "#16A085",
			metadata: map[string]interface{}{
				"location":     "Lab E",
				"type":         "vibration-sensor",
				"manufacturer": "VibeTech",
				"firmware":     "v2.1.3",
				"sample":       true,
			},
		},
		{
			id:        "device-027",
			tags:      []string{"production", "warehouse", "sensor"},
			icon:      "Gauge",
			iconColor: "#8E44AD",
			metadata: map[string]interface{}{
				"location":     "Warehouse A",
				"type":         "sound-sensor",
				"manufacturer": "AudioSense",
				"firmware":     "v1.5.0",
				"sample":       true,
			},
		},
		{
			id:        "device-028",
			tags:      []string{"staging", "test", "controller"},
			icon:      "Cpu",
			iconColor: "#27AE60",
			metadata: map[string]interface{}{
				"location":     "Test Lab D",
				"type":         "display-controller",
				"manufacturer": "DisplayTech",
				"firmware":     "v2.9.1",
				"sample":       true,
			},
		},
		{
			id:        "device-029",
			tags:      []string{"production", "field", "sensor"},
			icon:      "Gauge",
			iconColor: "#2ECC71",
			metadata: map[string]interface{}{
				"location":     "Field Site H",
				"type":         "battery-monitor",
				"manufacturer": "PowerSense",
				"firmware":     "v1.2.7",
				"sample":       true,
			},
		},
		{
			id:        "device-030",
			tags:      []string{"production", "warehouse", "gateway"},
			icon:      "Radio",
			iconColor: "#E84393",
			metadata: map[string]interface{}{
				"location":     "Warehouse B",
				"type":         "zigbee-gateway",
				"manufacturer": "ZigTech",
				"firmware":     "v3.1.0",
				"sample":       true,
			},
		},
		{
			id:        "device-031",
			tags:      []string{"development", "lab", "sensor"},
			icon:      "Activity",
			iconColor: "#00B894",
			metadata: map[string]interface{}{
				"location":     "Lab F",
				"type":         "gps-tracker",
				"manufacturer": "NaviTech",
				"firmware":     "v2.4.2",
				"sample":       true,
			},
		},
		{
			id:        "device-032",
			tags:      []string{"staging", "warehouse", "actuator"},
			icon:      "Zap",
			iconColor: "#636E72",
			metadata: map[string]interface{}{
				"location":     "Warehouse E",
				"type":         "smart-lock",
				"manufacturer": "SecureTech",
				"firmware":     "v4.0.3",
				"sample":       true,
			},
		},
		{
			id:        "device-033",
			tags:      []string{"production", "field", "controller"},
			icon:      "Cpu",
			iconColor: "#B2BEC3",
			metadata: map[string]interface{}{
				"location":     "Field Site I",
				"type":         "edge-server",
				"manufacturer": "EdgeCompute",
				"firmware":     "v3.7.1",
				"sample":       true,
			},
		},
		{
			id:        "device-034",
			tags:      []string{"production", "warehouse", "sensor"},
			icon:      "Activity",
			iconColor: "#0984E3",
			metadata: map[string]interface{}{
				"location":     "Warehouse F",
				"type":         "motion-detector",
				"manufacturer": "SecuritySense",
				"firmware":     "v2.6.0",
				"sample":       true,
			},
		},
		{
			id:        "device-035",
			tags:      []string{"development", "lab", "gateway"},
			icon:      "Router",
			iconColor: "#74B9FF",
			metadata: map[string]interface{}{
				"location":     "Lab G",
				"type":         "cellular-gateway",
				"manufacturer": "MobileNet",
				"firmware":     "v1.9.4",
				"sample":       true,
			},
		},
		{
			id:        "device-036",
			tags:      []string{"staging", "test", "sensor"},
			icon:      "Thermometer",
			iconColor: "#FD79A8",
			metadata: map[string]interface{}{
				"location":     "Test Lab E",
				"type":         "location-beacon",
				"manufacturer": "BeaconTech",
				"firmware":     "v1.4.5",
				"sample":       true,
			},
		},
		{
			id:        "device-037",
			tags:      []string{"production", "field", "actuator"},
			icon:      "Zap",
			iconColor: "#6C5CE7",
			metadata: map[string]interface{}{
				"location":     "Field Site J",
				"type":         "valve-controller",
				"manufacturer": "FlowTech",
				"firmware":     "v2.2.1",
				"sample":       true,
			},
		},
		{
			id:        "device-038",
			tags:      []string{"production", "warehouse", "controller"},
			icon:      "Cpu",
			iconColor: "#A29BFE",
			metadata: map[string]interface{}{
				"location":     "Warehouse G",
				"type":         "inventory-tracker",
				"manufacturer": "StockSys",
				"firmware":     "v3.4.0",
				"sample":       true,
			},
		},
		{
			id:        "device-039",
			tags:      []string{"development", "lab", "sensor"},
			icon:      "Gauge",
			iconColor: "#FF7675",
			metadata: map[string]interface{}{
				"location":     "Lab H",
				"type":         "proximity-sensor",
				"manufacturer": "RangeTech",
				"firmware":     "v1.6.2",
				"sample":       true,
			},
		},
		{
			id:        "device-040",
			tags:      []string{"staging", "warehouse", "camera"},
			icon:      "Camera",
			iconColor: "#FDCB6E",
			metadata: map[string]interface{}{
				"location":     "Warehouse H",
				"type":         "surveillance-camera",
				"manufacturer": "WatchTech",
				"firmware":     "v4.5.1",
				"sample":       true,
			},
		},
		{
			id:        "device-041",
			tags:      []string{"production", "field", "sensor"},
			icon:      "Activity",
			iconColor: "#00CEC9",
			metadata: map[string]interface{}{
				"location":     "Field Site K",
				"type":         "compass-sensor",
				"manufacturer": "OrientTech",
				"firmware":     "v1.3.6",
				"sample":       true,
			},
		},
		{
			id:        "device-042",
			tags:      []string{"production", "warehouse", "gateway"},
			icon:      "Radio",
			iconColor: "#FD79A8",
			metadata: map[string]interface{}{
				"location":     "Warehouse I",
				"type":         "lora-gateway",
				"manufacturer": "LoRaNet",
				"firmware":     "v2.7.0",
				"sample":       true,
			},
		},
		{
			id:        "device-043",
			tags:      []string{"development", "lab", "controller"},
			icon:      "Cpu",
			iconColor: "#55EFC4",
			metadata: map[string]interface{}{
				"location":     "Lab I",
				"type":         "motor-controller",
				"manufacturer": "MotionDrive",
				"firmware":     "v3.0.5",
				"sample":       true,
			},
		},
		{
			id:        "device-044",
			tags:      []string{"staging", "test", "actuator"},
			icon:      "Zap",
			iconColor: "#FF6348",
			metadata: map[string]interface{}{
				"location":     "Test Lab F",
				"type":         "notification-device",
				"manufacturer": "AlertSys",
				"firmware":     "v2.1.4",
				"sample":       true,
			},
		},
		{
			id:        "device-045",
			tags:      []string{"production", "field", "sensor"},
			icon:      "Gauge",
			iconColor: "#2D3436",
			metadata: map[string]interface{}{
				"location":     "Field Site L",
				"type":         "distance-sensor",
				"manufacturer": "RangeFinder",
				"firmware":     "v1.7.8",
				"sample":       true,
			},
		},
		{
			id:        "device-046",
			tags:      []string{"production", "warehouse", "sensor"},
			icon:      "Activity",
			iconColor: "#DFE6E9",
			metadata: map[string]interface{}{
				"location":     "Warehouse J",
				"type":         "rotation-sensor",
				"manufacturer": "SpinTech",
				"firmware":     "v2.0.2",
				"sample":       true,
			},
		},
		{
			id:        "device-047",
			tags:      []string{"development", "lab", "gateway"},
			icon:      "Router",
			iconColor: "#A29BFE",
			metadata: map[string]interface{}{
				"location":     "Lab J",
				"type":         "mqtt-gateway",
				"manufacturer": "MQTTHub",
				"firmware":     "v3.2.7",
				"sample":       true,
			},
		},
		{
			id:        "device-048",
			tags:      []string{"staging", "warehouse", "controller"},
			icon:      "Cpu",
			iconColor: "#00B894",
			metadata: map[string]interface{}{
				"location":     "Warehouse K",
				"type":         "analytics-device",
				"manufacturer": "DataTech",
				"firmware":     "v4.1.0",
				"sample":       true,
			},
		},
		{
			id:        "device-049",
			tags:      []string{"production", "field", "actuator"},
			icon:      "Zap",
			iconColor: "#FDCB6E",
			metadata: map[string]interface{}{
				"location":     "Field Site M",
				"type":         "relay-switch",
				"manufacturer": "SwitchTech",
				"firmware":     "v1.5.9",
				"sample":       true,
			},
		},
		{
			id:        "device-050",
			tags:      []string{"production", "warehouse", "sensor"},
			icon:      "Fan",
			iconColor: "#6C5CE7",
			metadata: map[string]interface{}{
				"location":     "Warehouse L",
				"type":         "time-sync-device",
				"manufacturer": "ChronoTech",
				"firmware":     "v2.8.3",
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

// importKeyAndCreateCA imports a private key into KMS and creates a CA using that key
func importKeyAndCreateCA(ctx context.Context, logger *logrus.Entry, kmsService services.KMSService, caService services.CAService, profileID string) (string, error) {
	// Parse the embedded private key
	block, _ := pem.Decode(embeddedPrivateKey)
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM block containing private key")
	}

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse EC private key: %w", err)
	}

	// Step 1: Import the private key into KMS
	logger.Info("Importing private key into KMS...")
	importedKey, err := kmsService.ImportKey(ctx, services.ImportKeyInput{
		PrivateKey: privateKey,
		Name:       "Sample Imported Root CA Key",
		Tags:       []string{"sample", "root-ca"},
		Metadata: map[string]any{
			"sample":      true,
			"description": "Imported ECDSA P-256 key for sample root CA",
		},
	})
	if err != nil {
		return "", fmt.Errorf("failed to import key into KMS: %w", err)
	}
	logger.Infof("Successfully imported key into KMS: %s", importedKey.KeyID)

	// Step 2: Create the CA using the imported key
	logger.Info("Creating CA with imported key...")
	caID := "sample-imported-root-ca"
	createdCA, err := caService.CreateCA(ctx, services.CreateCAInput{
		ID: caID,
		Subject: models.Subject{
			CommonName:       "Sample Imported Root CA",
			Organization:     "LamassuIoT Sample",
			OrganizationUnit: "Development",
			State:            "Gipuzkoa",
			Locality:         "Arrasate",
		},
		KeyMetadata: models.KeyMetadata{
			KeyID: importedKey.KeyID, // Use the imported key
			Type:  models.KeyType(x509.ECDSA),
			Bits:  256,
		},
		CAExpiration: models.Validity{
			Type:     models.Duration,
			Duration: models.TimeDuration(3650 * 24 * time.Hour), // 10 years
		},
		ProfileID: profileID,
		EngineID:  "golang-1", // Use default software engine
		Metadata: map[string]any{
			"sample": true,
			"type":   "imported-root",
		},
	})
	if err != nil {
		return "", fmt.Errorf("failed to create CA with imported key: %w", err)
	}

	return createdCA.ID, nil
}

// issueSampleCertificates issues a set of sample certificates from the specified CA
func issueSampleCertificates(ctx context.Context, logger *logrus.Entry, caService services.CAService, caID, caType string, profileIDs map[string]string) error {
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

		// Get the profile ID for this certificate type
		profileID, ok := profileIDs[certSpec.certType]
		if !ok {
			logger.Warnf("No profile ID found for cert type %s, skipping", certSpec.certType)
			continue
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
