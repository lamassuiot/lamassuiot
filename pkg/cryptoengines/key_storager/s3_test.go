package keystorager

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"

	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/helpers"
	awskmssm_test "github.com/lamassuiot/lamassuiot/v2/pkg/test/subsystems/cryptoengines/aws-kms-sm"
)

type CustomResolver struct {
	*net.Resolver
}

func (r *CustomResolver) LookupIP(host string) ([]net.IP, error) {
	if host == "example.com" {
		// Return the desired IP address for the specific domain
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	}

	// Use the default resolver for other domains
	return r.Resolver.LookupIP(context.Background(), "ip", host)
}

func setupS3(t *testing.T) (func(), *AWSS3KeyStorager) {
	// Create a new instance of GoCryptoEngine
	log := helpers.SetupLogger(config.Trace, "CA TestCase", "Golang Engine")
	bucketName := "my-bucket"

	teardown, awsSdkCfg, err := awskmssm_test.RunAWSEmulationLocalStackDocker()
	if err != nil {
		log.Fatalf("Could not launch AWS Platform: %s", err)
	}

	awsCfg, err := config.GetAwsSdkConfig(*awsSdkCfg)
	if err != nil {
		log.Warnf("Skipping AWS S3 engine with id %s: %s", awsCfg.AppID, err)
	}
	engine, err := NewS3Storager(log, *awsCfg, bucketName)

	if err != nil {
		log.Warnf("Skipping AWS S3 engine with id %s: %s", awsCfg.AppID, err)
	}

	return func() {
		teardown()
	}, engine.(*AWSS3KeyStorager)

}

func TestGetValueByID(t *testing.T) {
	teardown, engine := setupS3(t)
	defer teardown()
	keyID := "test-key"

	err := engine.Create(keyID, []byte("value-storage"))
	if err != nil {
		t.Fatalf("Failed to create value in S3: %s", err)
	}

	// Test case: Get value by ID
	t.Run("GetValueByID", func(t *testing.T) {
		_, err = engine.Get(keyID)
		if err != nil {
			t.Errorf("Unexpected value type loading from S3 for ID '%s'", keyID) //Aqui como no existe el objeto signer, se definido el errorf aqui, en el caso de que no lea bien la calve privada.
		}
		t.Logf("The value has loaded from S3 with the following ID '%s'", keyID)

	})

	// Test case: Get value by non-existent ID
	t.Run("GetValueByNonExistentID", func(t *testing.T) {
		nonExistentValueID := "non-existent-value"
		_, err := engine.Get(nonExistentValueID)
		if !errors.Is(err, os.ErrNotExist) {
			t.Logf("Expected error os.ErrNotExist, got: %s", err)
		}
	})
}
func TestCreateS3Value(t *testing.T) {
	teardown, engine := setupS3(t)
	defer teardown()
	keyID := "test-key"

	t.Run("CreateRSAValue", func(t *testing.T) {
		str := "value-storagefunc"
		err := engine.Create(keyID, []byte(str))
		if err != nil {
			t.Fatalf("Failed to create value in S3: %s", err)
		}
	})
}

func TestDeleteValue(t *testing.T) {
	teardown, engine := setupS3(t)
	defer teardown()
	keyID := "test-key"

	// Test case: Delete existing value
	t.Run("DeleteExistingValue", func(t *testing.T) {
		err := engine.Create(keyID, []byte("testing-valueStorage"))
		if err != nil {
			t.Logf("Expected error while creating the value to S3, got: %s", err)
		}
		err = engine.Delete(keyID)
		if err != nil {
			t.Errorf("Failed to delete existing value in S3: %s", err)
		}
		_, err = engine.Get(keyID)

		if err != nil {
			t.Logf("Expected error while accesing to S3 to find the value, got: %s", err)
		}
	})

	// Test case: Delete non-existent value
	t.Run("DeleteNonExistentValue", func(t *testing.T) {
		nonExistentValueID := "non-existent-value"
		err := engine.Delete(nonExistentValueID)

		if err != nil {
			t.Errorf("Expected error while accesing to S3 to find the value that does not exist, got: %s", err)
		}
	})
}
