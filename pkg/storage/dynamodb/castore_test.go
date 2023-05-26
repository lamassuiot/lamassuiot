package dynamodb

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/lamassuiot/lamassuiot/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/pkg/models"
	"github.com/lamassuiot/lamassuiot/pkg/storage"
)

func createCA(id string) *models.CACertificate {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"Test"},
			Country:       []string{"Test"},
			Province:      []string{"Test"},
			Locality:      []string{"Test"},
			StreetAddress: []string{"Test"},
			PostalCode:    []string{"Test"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caMetadata := models.CAMetadata{
		Name: "Test",
		Type: models.CATypePKI,
	}

	return &models.CACertificate{
		ID:               id,
		IssuanceDuration: models.TimeDuration(time.Duration(1)),
		Metadata:         caMetadata,
		CreationTS:       time.Now(),
		Certificate: models.Certificate{
			Fingerprint:  helpers.X509CertFingerprint(*ca),
			Certificate:  (*models.X509Certificate)(ca),
			Status:       models.StatusActive,
			SerialNumber: helpers.SerialNumberToString(ca.SerialNumber),
			KeyMetadata: models.KeyStrengthMetadata{
				Type:     models.KeyType(x509.RSA),
				Bits:     4096,
				Strength: models.KeyStrengthHigh,
			},
			Subject: models.Subject{
				CommonName: ca.Subject.CommonName,
			},
			ValidFrom: ca.NotBefore,
			ValidTo:   ca.NotAfter,
			IssuerCAMetadata: models.IssuerCAMetadata{
				SerialNumber: ca.Subject.SerialNumber,
				CAID:         id,
			},
		},
	}
}

func setup(t *testing.T, tableName, region, accessKeyID, secretAccessKey, url string) (context.Context, storage.CACertificatesRepo, error) {
	ctx := context.TODO()
	dynamodb, err := NewDynamoDBCARepository(ctx, tableName, region, accessKeyID, secretAccessKey, url)
	if err != nil {
		return nil, nil, err
	}
	t.Cleanup(func() {
		ctx := context.TODO()
		err := dynamodb.(*DynamoDBCAStorage).Clean(ctx)
		if err != nil {
			t.Fatalf("Error cleaning database: %v", err)
		}
	})
	return ctx, dynamodb, nil
}

func TestPreviouslyInsertedCA(t *testing.T) {
	ctx, dynamodb, err := setup(t, "lamassuiot", "default", "custom", "custom", "http://localhost:8000")
	if err != nil {
		t.Fatalf("Connection with DynamoDB not stablished: %v", err)
	}
	caCertificate := createCA("Test")
	out, err := dynamodb.Insert(ctx, caCertificate)
	if err != nil {
		t.Fatalf("Unable to insert CA certificate: %v", err)
	}
	if out.ID != caCertificate.ID {
		t.Errorf("Expected id to be %s and found is %s", caCertificate.ID, out.ID)
	}
	_, err = dynamodb.Insert(ctx, caCertificate)
	if err != nil {
		if dbError := new(types.ConditionalCheckFailedException); !errors.As(err, &dbError) {
			t.Errorf("Expected ConditionalCheckFailedException but, %v found", err)
		}

	}
}

func TestInsertCA(t *testing.T) {
	ctx, dynamodb, err := setup(t, "lamassuiot", "default", "custom", "custom", "http://localhost:8000")
	if err != nil {
		t.Fatalf("Connection with DynamoDB not stablished: %v", err)
	}

	caCertificate := createCA("Test")
	out, err := dynamodb.Insert(ctx, caCertificate)
	if err != nil {
		t.Fatalf("Unable to insert CA certificate: %v", err)
	}
	if out.ID != caCertificate.ID {
		t.Errorf("Expected id to be %s and found is %s", caCertificate.ID, out.ID)
	}
}

func TestGetCADoesNotExist(t *testing.T) {
	ctx, dynamodb, err := setup(t, "lamassuiot", "default", "custom", "custom", "http://localhost:8000")
	if err != nil {
		t.Fatalf("Connection with DynamoDB not stablished: %v", err)
	}
	out, err := dynamodb.Select(ctx, "Test")
	if err != nil {
		t.Fatalf("Unable to read CA certificate %v", err)
	}
	if out != nil {
		t.Error("Expected output to be nil, because no CA is inserted")
	}
}

func TestUpdateCADoesNotExist(t *testing.T) {
	ctx, dynamodb, err := setup(t, "lamassuiot", "default", "custom", "custom", "http://localhost:8000")
	if err != nil {
		t.Fatalf("Connection with DynamoDB not stablished: %v", err)
	}
	caCertificate := createCA("Test")
	_, err = dynamodb.Update(ctx, caCertificate)
	if err != nil {
		if dbError := new(types.ConditionalCheckFailedException); !errors.As(err, &dbError) {
			t.Errorf("Expected ConditionalCheckFailedException but, %v found", err)
		}
	}
}

func TestUpdateCA(t *testing.T) {
	ctx, dynamodb, err := setup(t, "lamassuiot", "default", "custom", "custom", "http://localhost:8000")
	if err != nil {
		t.Fatalf("Connection with DynamoDB not stablished: %v", err)
	}
	caCertificate := createCA("Test")
	inserted, err := dynamodb.Insert(ctx, caCertificate)
	if err != nil {
		t.Fatalf("Unable to update CA certificate %v", err)
	}
	if inserted.ID != caCertificate.ID {
		t.Errorf("Expected id to be %s and found is %s", caCertificate.ID, inserted.ID)
	}
	inserted.Fingerprint = "randomFingerprint"
	updated, err := dynamodb.Update(ctx, inserted)
	if err != nil {
		t.Fatalf("Unable to update CA certificate %v", err)
	}
	if updated.Fingerprint != "randomFingerprint" {
		t.Errorf("Expected fingerprint to be %s and found is %s", "randomFingerprint", updated.Fingerprint)
	}
}
