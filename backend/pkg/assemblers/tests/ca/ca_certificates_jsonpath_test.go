package ca

import (
	"context"
	"strconv"
	"testing"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/assemblers/tests"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

type jsonPathTestCase struct {
	name          string
	jsonPath      string
	expectedCount int
	expectedCerts []string // serial numbers to match
}

func TestGetCertificatesFilterByMetadataJsonPath(t *testing.T) {
	// Setup server once for all tests
	serverTest, err := tests.TestServiceBuilder{}.WithDatabase("ca", "kms").Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	caTest := serverTest.CA

	// Ensure clean DB and init CA
	if err := serverTest.BeforeEach(); err != nil {
		t.Fatalf("failed running BeforeEach: %s", err)
	}
	_, err = initCA(caTest.Service)
	if err != nil {
		t.Fatalf("failed to init CA: %s", err)
	}

	// Create all certificates needed for all tests
	certs := make(map[string]*models.Certificate)

	// Certificates for basic tests
	_, cert1, err := createCAAndCertificate(caTest.Service)
	if err != nil {
		t.Fatalf("failed to create cert1: %s", err)
	}
	certs["basic_prod"] = cert1

	_, cert2, err := createCAAndCertificate(caTest.Service)
	if err != nil {
		t.Fatalf("failed to create cert2: %s", err)
	}
	certs["basic_staging"] = cert2

	// Certificates for complex nested metadata
	_, cert3, err := createCAAndCertificate(caTest.Service)
	if err != nil {
		t.Fatalf("failed to create cert3: %s", err)
	}
	certs["complex_prod"] = cert3

	_, cert4, err := createCAAndCertificate(caTest.Service)
	if err != nil {
		t.Fatalf("failed to create cert4: %s", err)
	}
	certs["complex_staging"] = cert4

	// Certificate for no-match test
	_, cert5, err := createCAAndCertificate(caTest.Service)
	if err != nil {
		t.Fatalf("failed to create cert5: %s", err)
	}
	certs["nomatch"] = cert5

	// Certificates for value matching
	_, cert6, err := createCAAndCertificate(caTest.Service)
	if err != nil {
		t.Fatalf("failed to create cert6: %s", err)
	}
	certs["value_prod"] = cert6

	_, cert7, err := createCAAndCertificate(caTest.Service)
	if err != nil {
		t.Fatalf("failed to create cert7: %s", err)
	}
	certs["value_staging"] = cert7

	_, cert8, err := createCAAndCertificate(caTest.Service)
	if err != nil {
		t.Fatalf("failed to create cert8: %s", err)
	}
	certs["value_dev"] = cert8

	// Certificates for logical operators
	_, cert9, err := createCAAndCertificate(caTest.Service)
	if err != nil {
		t.Fatalf("failed to create cert9: %s", err)
	}
	certs["logical_prod_critical"] = cert9

	_, cert10, err := createCAAndCertificate(caTest.Service)
	if err != nil {
		t.Fatalf("failed to create cert10: %s", err)
	}
	certs["logical_prod_noncritical"] = cert10

	_, cert11, err := createCAAndCertificate(caTest.Service)
	if err != nil {
		t.Fatalf("failed to create cert11: %s", err)
	}
	certs["logical_staging_critical"] = cert11

	// Certificates for array operations
	_, cert12, err := createCAAndCertificate(caTest.Service)
	if err != nil {
		t.Fatalf("failed to create cert12: %s", err)
	}
	certs["array_prod_web"] = cert12

	_, cert13, err := createCAAndCertificate(caTest.Service)
	if err != nil {
		t.Fatalf("failed to create cert13: %s", err)
	}
	certs["array_staging_api"] = cert13

	_, cert14, err := createCAAndCertificate(caTest.Service)
	if err != nil {
		t.Fatalf("failed to create cert14: %s", err)
	}
	certs["array_prod_api"] = cert14

	// Certificates for string operations
	_, cert15, err := createCAAndCertificate(caTest.Service)
	if err != nil {
		t.Fatalf("failed to create cert15: %s", err)
	}
	certs["string_web1"] = cert15

	_, cert16, err := createCAAndCertificate(caTest.Service)
	if err != nil {
		t.Fatalf("failed to create cert16: %s", err)
	}
	certs["string_api"] = cert16

	_, cert17, err := createCAAndCertificate(caTest.Service)
	if err != nil {
		t.Fatalf("failed to create cert17: %s", err)
	}
	certs["string_web2"] = cert17

	// Certificates for type checking
	_, cert18, err := createCAAndCertificate(caTest.Service)
	if err != nil {
		t.Fatalf("failed to create cert18: %s", err)
	}
	certs["type_mixed"] = cert18

	_, cert19, err := createCAAndCertificate(caTest.Service)
	if err != nil {
		t.Fatalf("failed to create cert19: %s", err)
	}
	certs["type_simple"] = cert19

	// Certificates for numeric ranges
	for i := 1; i <= 5; i++ {
		_, cert, err := createCAAndCertificate(caTest.Service)
		if err != nil {
			t.Fatalf("failed to create numeric cert %d: %s", i, err)
		}
		certs[strconv.Itoa(i)] = cert
	}

	// Populate metadata for all certificates
	updateMetadata := func(serialNumber string, metadata map[string]interface{}) {
		_, err := caTest.Service.UpdateCertificateMetadata(context.Background(), services.UpdateCertificateMetadataInput{
			SerialNumber: serialNumber,
			Patches: chelpers.NewPatchBuilder().
				Add(chelpers.JSONPointerBuilder(), metadata).
				Build(),
		})
		if err != nil {
			t.Fatalf("failed to update metadata for %s: %s", serialNumber, err)
		}
	}

	// Basic metadata
	updateMetadata(certs["basic_prod"].SerialNumber, map[string]interface{}{
		"environment": "production",
		"region":      "us-west-1",
	})
	updateMetadata(certs["basic_staging"].SerialNumber, map[string]interface{}{
		"environment": "staging",
		"region":      "us-east-1",
	})

	// Complex nested metadata
	updateMetadata(certs["complex_prod"].SerialNumber, map[string]interface{}{
		"tags": []map[string]interface{}{
			{"key": "production", "value": "true"},
			{"key": "critical", "value": "high"},
		},
		"owner": map[string]interface{}{
			"team":    "platform",
			"contact": "platform@example.com",
		},
	})
	updateMetadata(certs["complex_staging"].SerialNumber, map[string]interface{}{
		"tags": []map[string]interface{}{
			{"key": "staging", "value": "true"},
			{"key": "critical", "value": "low"},
		},
		"owner": map[string]interface{}{
			"team":    "development",
			"contact": "dev@example.com",
		},
	})

	// No-match metadata
	updateMetadata(certs["nomatch"].SerialNumber, map[string]interface{}{
		"environment": "production",
	})

	// Value matching metadata
	updateMetadata(certs["value_prod"].SerialNumber, map[string]interface{}{
		"environment": "production",
		"version":     2,
		"critical":    true,
	})
	updateMetadata(certs["value_staging"].SerialNumber, map[string]interface{}{
		"environment": "staging",
		"version":     1,
		"critical":    false,
	})
	updateMetadata(certs["value_dev"].SerialNumber, map[string]interface{}{
		"environment": "development",
		"version":     3,
		"critical":    true,
	})

	// Logical operators metadata
	updateMetadata(certs["logical_prod_critical"].SerialNumber, map[string]interface{}{
		"environment": "production",
		"critical":    true,
		"version":     2,
	})
	updateMetadata(certs["logical_prod_noncritical"].SerialNumber, map[string]interface{}{
		"environment": "production",
		"critical":    false,
		"version":     1,
	})
	updateMetadata(certs["logical_staging_critical"].SerialNumber, map[string]interface{}{
		"environment": "staging",
		"critical":    true,
		"version":     3,
	})

	// Array operations metadata
	updateMetadata(certs["array_prod_web"].SerialNumber, map[string]interface{}{
		"tags":  []string{"production", "web", "frontend"},
		"ports": []int{80, 443},
	})
	updateMetadata(certs["array_staging_api"].SerialNumber, map[string]interface{}{
		"tags":  []string{"staging", "api", "backend"},
		"ports": []int{8080, 8443},
	})
	updateMetadata(certs["array_prod_api"].SerialNumber, map[string]interface{}{
		"tags":  []string{"production", "api"},
		"ports": []int{443, 8080},
	})

	// String operations metadata
	updateMetadata(certs["string_web1"].SerialNumber, map[string]interface{}{
		"hostname":    "web-server-01.example.com",
		"description": "Production Web Server",
	})
	updateMetadata(certs["string_api"].SerialNumber, map[string]interface{}{
		"hostname":    "api-gateway-01.example.com",
		"description": "API Gateway Instance",
	})
	updateMetadata(certs["string_web2"].SerialNumber, map[string]interface{}{
		"hostname":    "web-server-02.example.com",
		"description": "Staging Environment",
	})

	// Type checking metadata
	updateMetadata(certs["type_mixed"].SerialNumber, map[string]interface{}{
		"stringField": "test",
		"numberField": 42,
		"boolField":   true,
		"arrayField":  []string{"a", "b"},
		"objectField": map[string]string{"key": "value"},
		"nullField":   nil,
	})
	updateMetadata(certs["type_simple"].SerialNumber, map[string]interface{}{
		"stringField": "another",
		"numberField": 100,
	})

	// Numeric ranges metadata
	for i := 1; i <= 5; i++ {
		updateMetadata(certs[strconv.Itoa(i)].SerialNumber, map[string]interface{}{
			"score":    i * 20,
			"priority": float64(i) * 1.5,
		})
	}

	// Define all test cases
	testCases := []jsonPathTestCase{
		// Basic existence tests
		{"exists environment", "exists($.environment)", 9, nil},
		{"exists region", "exists($.region)", 2, nil},

		// Complex nested tests
		{"tags with production key", `exists($.tags[*] ? (@.key == "production"))`, 1, []string{certs["complex_prod"].SerialNumber}},
		{"owner.team exists", "exists($.owner.team)", 2, nil},
		{"tags[0].key exists", "exists($.tags[0].key)", 2, nil},

		// No match test
		{"nonexistent field", "exists($.nonexistent.field)", 0, nil},

		// Value matching tests
		{`environment == "production"`, `$.environment == "production"`, 5, nil},
		{`environment != "production"`, `$.environment != "production"`, 4, nil},
		{"version > 1", "$.version > 1", 4, nil},
		{"version <= 2", "$.version <= 2", 4, nil},
		{"critical == true", "$.critical == true", 4, nil},

		// Logical operators tests
		{`production AND critical`, `$.environment == "production" && $.critical == true`, 2, nil},
		{`staging OR version > 2`, `$.environment == "staging" || $.version > 2`, 4, nil},
		{"critical == false", "$.critical == false", 2, nil},
		{`(production OR staging) AND critical`, `($.environment == "production" || $.environment == "staging") && $.critical == true`, 3, nil},

		// Array operations tests
		{`tags contains "production"`, `exists($.tags[*] ? (@ == "production"))`, 2, nil},
		{`tags[0] == "staging"`, `$.tags[0] == "staging"`, 1, []string{certs["array_staging_api"].SerialNumber}},
		{"ports > 8000", "exists($.ports[*] ? (@ > 8000))", 2, nil},
		{`tags[last] == "backend"`, `$.tags[last] == "backend"`, 1, nil},
		{`tags contains "production" AND "api"`, `exists($.tags[*] ? (@ == "production")) && exists($.tags[*] ? (@ == "api"))`, 1, []string{certs["array_prod_api"].SerialNumber}},

		// String operations tests
		{`hostname starts with "web"`, `$.hostname starts with "web"`, 2, nil},
		{`hostname regex "^api.*"`, `$.hostname like_regex "^api.*"`, 1, []string{certs["string_api"].SerialNumber}},
		{`description regex "PRODUCTION" flag "i"`, `$.description like_regex "PRODUCTION" flag "i"`, 1, nil},

		// Type checking tests
		{`numberField.type() == "number"`, `$.numberField.type() == "number"`, 2, nil},
		{`arrayField.type() == "array"`, `$.arrayField.type() == "array"`, 1, nil},
		{`objectField.type() == "object"`, `$.objectField.type() == "object"`, 1, nil},
		{"boolField exists", "exists($.boolField)", 1, nil},

		// Numeric ranges tests
		{"score > 50", "$.score > 50", 3, nil},
		{"score <= 60", "$.score <= 60", 3, nil},
		{"score range 40-80", "$.score >= 40 && $.score <= 80", 3, nil},
		{"priority > 4.5", "$.priority > 4.5", 2, nil},
	}

	// Execute all test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			found := []*models.Certificate{}
			qp := &resources.QueryParameters{
				PageSize: 50,
				Filters: []resources.FilterOption{
					{
						Field:           "metadata",
						Value:           tc.jsonPath,
						FilterOperation: resources.JsonPathExpression,
					},
				},
			}

			_, err := caTest.HttpCASDK.GetCertificates(context.Background(), services.GetCertificatesInput{
				ListInput: resources.ListInput[models.Certificate]{
					QueryParameters: qp,
					ExhaustiveRun:   true,
					ApplyFunc: func(elem models.Certificate) {
						found = append(found, &elem)
					},
				},
			})
			if err != nil {
				t.Fatalf("GetCertificates returned error: %s", err)
			}

			if len(found) != tc.expectedCount {
				t.Errorf("expected %d certificates, got %d", tc.expectedCount, len(found))
			}

			if tc.expectedCerts != nil {
				foundSerials := make(map[string]bool)
				for _, cert := range found {
					foundSerials[cert.SerialNumber] = true
				}
				for _, expectedSerial := range tc.expectedCerts {
					if !foundSerials[expectedSerial] {
						t.Errorf("expected to find certificate %s", expectedSerial)
					}
				}
			}
		})
	}
}
