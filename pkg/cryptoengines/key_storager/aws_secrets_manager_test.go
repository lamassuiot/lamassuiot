package keystorager

import (
	"testing"

	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/helpers"
	awskmssm_test "github.com/lamassuiot/lamassuiot/v2/pkg/test/subsystems/cryptoengines/aws-kms-sm"
)

func setupAWSSecrets(t *testing.T) (func(), *AWSSecretsManagerKeyStorager) {

	// Create a new instance of GoCryptoEngine
	log := helpers.SetupLogger(config.Info, "CA TestCase", "Golang Engine")

	teardown, awsSdkCfg, err := awskmssm_test.RunAWSEmulationLocalStackDocker()
	if err != nil {
		log.Fatalf("could not launch AWS Platform: %s", err)
	}

	awsCfg, err := config.GetAwsSdkConfig(*awsSdkCfg)
	if err != nil {
		log.Warnf("skipping AWS S3 engine with id %s: %s", awsCfg.AppID, err)
	}
	engine, err := NewAWSSecretManagerKeyStorage(log, *awsCfg)

	if err != nil {
		log.Warnf("skipping AWS S3 engine with id %s: %s", awsCfg.AppID, err)
	}

	return func() {
		teardown()
	}, engine.(*AWSSecretsManagerKeyStorager)
}
func TestCreateAWSSecretKey(t *testing.T) {
	teardown, engine := setupAWSSecrets(t)
	defer teardown()

	keyID := "test-key"

	t.Run("CreateKey", func(t *testing.T) {
		str := "key-storagefunc"
		err := engine.Create(keyID, []byte(str))
		if err != nil {
			t.Fatalf("Failed to create the value in aws secret manager: %s", err)
		}

		_, err = engine.Get(keyID)

		if err != nil {
			t.Errorf("Unexpected error while accesing to the aws secret value created in the previous step: %s", err)
		}
	})
}

func TestDeleteAWSSecretKey(t *testing.T) {
	teardown, engine := setupAWSSecrets(t)
	defer teardown()
	keyID := "test-key"

	// Test case: Delete existing value
	t.Run("DeleteExistingValue", func(t *testing.T) {
		err := engine.Create(keyID, []byte("testing-valueStorage"))
		if err != nil {
			t.Fatalf("Got an error while creating the value in the AWS secret: %s", err)
		}
		err = engine.Delete(keyID)
		if err != nil {
			t.Fatalf("Failed to delete existing value in the AWS secret: %s", err)
		}
		//Aqui no se ha hecho un get, porque daba error a la hora de intentar cargar un valor que esta eliminada de forma predeterminada
	})

	// Test case: Delete non-existent key
	t.Run("DeleteNonExistentValue", func(t *testing.T) {
		nonExistentValueID := "non-existent-value"
		err := engine.Delete(nonExistentValueID)
		if err != nil {
			t.Logf("Expected an error while accesing to AWS secret to find the value that does not exist, got: %s", err)
		} else {
			t.Error("Expected an error while deleteting a non existent value, but it does not return any error")
		}
	})
}

func TestGetAWSSecretValueByID(t *testing.T) {
	teardown, engine := setupAWSSecrets(t)

	defer teardown()
	keyID := "test-key"

	err := engine.Create(keyID, []byte("value-storage"))

	// Test case: Get the value by ID
	t.Run("GetValueByID", func(t *testing.T) {
		_, err = engine.Get(keyID)
		if err != nil {
			t.Errorf("Unexpected error while accessing to AWS secret the value with the ID '%s'", keyID) //Aqui como no existe el objeto signer, se definido el errorf aqui, en el caso de que no lea bien la calve privada.
		}
		t.Logf("The value has loaded from AWS secret with the following ID '%s'", keyID)
	})

	// Test case: Get value by non-existent ID
	t.Run("GetValueByNonExistentID", func(t *testing.T) {
		nonExistentValueID := "non-existent-value"
		_, err := engine.Get(nonExistentValueID)
		if err == nil {
			t.Error("Expected error, but it does not return any error")
		}
	})
}
