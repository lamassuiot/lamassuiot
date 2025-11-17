package aws

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
	"strings"
	"testing"

	laws "github.com/lamassuiot/lamassuiot/shared/aws/v3"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestNewAWSKMSEngine(t *testing.T) {
	logger := logrus.New().WithField("test", "NewAWSKMSEngine")
	awsConf := aws.Config{}
	metadata := map[string]interface{}{
		"key": "value",
	}

	engine, err := NewAWSKMSEngine(logger, awsConf, metadata)

	assert.NoError(t, err)
	assert.NotNil(t, engine)

	expectedConfig := models.CryptoEngineInfo{
		Type:          models.AWSKMS,
		SecurityLevel: models.SL2,
		Provider:      "Amazon Web Services",
		Name:          "KMS",
		Metadata:      metadata,
		SupportedKeyTypes: []models.SupportedKeyTypeInfo{
			{
				Type: models.KeyType(x509.RSA),
				Sizes: []int{
					2048,
					3072,
					4096,
				},
			},
			{
				Type: models.KeyType(x509.ECDSA),
				Sizes: []int{
					256,
					384,
					521,
				},
			},
		},
	}

	assert.Equal(t, expectedConfig, engine.GetEngineConfig())
}

func testDeleteKeyOnKMS(t *testing.T, engine cryptoengines.CryptoEngine) {
	awsengine := engine.(*AWSKMSCryptoEngine)
	err := awsengine.DeleteKey("test-key")
	assert.EqualError(t, err, "cannot delete key [test-key]. Go to your aws account and do it manually")
}

func TestAWSKMSCryptoEngine(t *testing.T) {
	cleanupBeforeTest, engine, err := prepareKMSCryptoEngine(t)
	if err != nil {
		t.Fatalf("Error preparing KMS engine: %v", err)
	}

	table := []struct {
		name     string
		function func(t *testing.T, engine cryptoengines.CryptoEngine)
	}{
		{"CreateECDSAPrivateKey", cryptoengines.SharedTestCreateECDSAPrivateKey},
		{"CreateRSAPrivateKey", cryptoengines.SharedTestCreateRSAPrivateKey},
		//TODO: LocalStack does not support RSA_PSS with fixed salt length. AWS KMS DOES support it. Follow issues:
		// - https://github.com/localstack/localstack/pull/11649
		// - https://github.com/localstack/localstack/issues/9602
		// {"SignRSA_PSS", cryptoengines.SharedTestRSAPSSSignature},
		{"SignRSA_PKCS1v1_5", cryptoengines.SharedTestRSAPKCS1v15Signature},
		{"SignECDSA", cryptoengines.SharedTestECDSASignature},
		// {"DeleteKey", cryptoengines.SharedTestDeleteKey},
		{"GetPrivateKeyByID", cryptoengines.SharedGetKey},
		{"GetPrivateKeyByIDNotFound", cryptoengines.SharedGetKeyNotFound},
		{"ListPrivateKeyIDs", cryptoengines.SharedListKeys},
		{"RenameKey", cryptoengines.SharedRenameKey},
		//TODO: LocalStack Has some open issues regarding KMS Import keys. Follow issues:
		// - https://github.com/localstack/localstack/issues/10921
		{"ImportRSAPrivateKey", cryptoengines.SharedTestImportRSAPrivateKey},
		{"ImportECDSAPrivateKey", cryptoengines.SharedTestImportECDSAPrivateKey},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			defer cleanupBeforeTest()
			tt.function(t, engine)
		})
	}
}

func prepareKMSCryptoEngine(t *testing.T) (func() error, cryptoengines.CryptoEngine, error) {
	beforeTestCleanup, containerCleanup, conf, err := laws.RunAWSEmulationLocalStackDocker(false)
	if err != nil {
		return nil, nil, err
	}

	t.Cleanup(func() { _ = containerCleanup() })

	logger := logrus.New().WithField("test", "KMS")

	metadata := map[string]any{}

	awsConf, err := laws.GetAwsSdkConfig(*conf)
	if err != nil {
		return nil, nil, err
	}

	engine, err := NewAWSKMSEngine(logger, *awsConf, metadata)
	if err != nil {
		return nil, nil, err
	}

	return beforeTestCleanup, engine, nil
}

// TestAWSKMSPaginationSupport tests that pagination works correctly
// when listing keys and aliases
func TestAWSKMSPaginationSupport(t *testing.T) {
	cleanupBeforeTest, engine, err := prepareKMSCryptoEngine(t)
	if err != nil {
		t.Fatalf("Error preparing KMS engine: %v", err)
	}
	defer cleanupBeforeTest()

	t.Run("ListPrivateKeyIDsPagination", func(t *testing.T) {
		// Create multiple keys to test pagination
		// Note: LocalStack may not enforce the 100-item limit strictly,
		// but this test validates that the pagination logic doesn't break
		// with multiple keys
		const numKeys = 10 // Using 10 keys for faster tests
		createdKeyIDs := make([]string, 0, numKeys)

		// Create test keys
		for range numKeys {
			keyID, _, err := engine.CreateECDSAPrivateKey(elliptic.P256())
			assert.NoError(t, err)
			createdKeyIDs = append(createdKeyIDs, keyID)
		}

		// List all keys - this should use pagination internally
		listedKeys, err := engine.ListPrivateKeyIDs()
		assert.NoError(t, err)
		assert.GreaterOrEqual(t, len(listedKeys), numKeys, "Should list at least the created keys")

		// Verify all created keys are in the list
		for _, createdID := range createdKeyIDs {
			assert.Contains(t, listedKeys, createdID, "Created key should be in the list")
		}
	})

	t.Run("GetPrivateKeyByIDWithMultipleKeys", func(t *testing.T) {
		defer cleanupBeforeTest()

		// Create multiple keys
		const numKeys = 5
		createdKeys := make(map[string]crypto.Signer)

		for range numKeys {
			keyID, signer, err := engine.CreateECDSAPrivateKey(elliptic.P256())
			assert.NoError(t, err)
			createdKeys[keyID] = signer
		}

		// Verify we can retrieve each key by ID (tests pagination in GetPrivateKeyByID)
		for keyID, expectedSigner := range createdKeys {
			retrievedSigner, err := engine.GetPrivateKeyByID(keyID)
			assert.NoError(t, err)
			assert.NotNil(t, retrievedSigner)
			assert.Equal(t, expectedSigner.Public(), retrievedSigner.Public(),
				"Retrieved key should match created key")
		}
	})

	t.Run("PaginationWithRenamedKeys", func(t *testing.T) {
		defer cleanupBeforeTest()

		// Create keys and rename them
		keyID1, _, err := engine.CreateECDSAPrivateKey(elliptic.P256())
		assert.NoError(t, err)

		keyID2, _, err := engine.CreateECDSAPrivateKey(elliptic.P256())
		assert.NoError(t, err)

		newKeyID1 := "renamed-key-1"
		newKeyID2 := "renamed-key-2"

		err = engine.RenameKey(keyID1, newKeyID1)
		assert.NoError(t, err)

		err = engine.RenameKey(keyID2, newKeyID2)
		assert.NoError(t, err)

		// List keys - should include renamed keys
		listedKeys, err := engine.ListPrivateKeyIDs()
		assert.NoError(t, err)

		assert.Contains(t, listedKeys, newKeyID1, "Should contain renamed key 1")
		assert.Contains(t, listedKeys, newKeyID2, "Should contain renamed key 2")
		assert.NotContains(t, listedKeys, keyID1, "Should not contain old key ID 1")
		assert.NotContains(t, listedKeys, keyID2, "Should not contain old key ID 2")

		// Retrieve renamed keys
		_, err = engine.GetPrivateKeyByID(newKeyID1)
		assert.NoError(t, err)

		_, err = engine.GetPrivateKeyByID(newKeyID2)
		assert.NoError(t, err)
	})
}

// TestAWSKMSHelperFunctions tests the new helper functions added for pagination
func TestAWSKMSHelperFunctions(t *testing.T) {
	cleanupBeforeTest, engine, err := prepareKMSCryptoEngine(t)
	if err != nil {
		t.Fatalf("Error preparing KMS engine: %v", err)
	}
	defer cleanupBeforeTest()

	awsEngine := engine.(*AWSKMSCryptoEngine)

	t.Run("getAllKMSKeys", func(t *testing.T) {
		// Create a few keys
		_, _, err := engine.CreateECDSAPrivateKey(elliptic.P256())
		assert.NoError(t, err)

		_, _, err = engine.CreateECDSAPrivateKey(elliptic.P256())
		assert.NoError(t, err)

		// Test getAllKMSKeys helper
		keys, err := awsEngine.getAllKMSKeys(context.Background())
		assert.NoError(t, err)
		assert.GreaterOrEqual(t, len(keys), 2, "Should return at least 2 keys")
	})

	t.Run("getAliasesForKey", func(t *testing.T) {
		defer cleanupBeforeTest()

		// Create a key
		keyID, _, err := engine.CreateECDSAPrivateKey(elliptic.P256())
		assert.NoError(t, err)

		// Get all keys to find the key ID
		keys, err := awsEngine.getAllKMSKeys(context.Background())
		assert.NoError(t, err)

		var targetKey *types.KeyListEntry
		for _, key := range keys {
			aliases, err := awsEngine.getAliasesForKey(context.Background(), key.KeyId)
			if err != nil {
				continue
			}

			for _, alias := range aliases {
				aliasName := strings.ReplaceAll(*alias.AliasName, "alias/", "")
				if aliasName == keyID {
					targetKey = &key
					break
				}
			}

			if targetKey != nil {
				break
			}
		}

		assert.NotNil(t, targetKey, "Should find the created key")

		// Test getAliasesForKey helper
		aliases, err := awsEngine.getAliasesForKey(context.Background(), targetKey.KeyId)
		assert.NoError(t, err)
		assert.Greater(t, len(aliases), 0, "Should return at least one alias")
	})

	t.Run("findKeyArnByAlias", func(t *testing.T) {
		defer cleanupBeforeTest()

		// Create a key
		keyID, _, err := engine.CreateECDSAPrivateKey(elliptic.P256())
		assert.NoError(t, err)

		// Test findKeyArnByAlias helper
		keyArn, err := awsEngine.findKeyArnByAlias(context.Background(), keyID)
		assert.NoError(t, err)
		assert.NotEmpty(t, keyArn, "Should return a valid key ARN")
		assert.Contains(t, keyArn, "arn:", "Key ARN should contain 'arn:'")

		// Test with non-existent alias
		_, err = awsEngine.findKeyArnByAlias(context.Background(), "non-existent-key")
		assert.Error(t, err)
		assert.Equal(t, "kms key not found", err.Error())
	})

	t.Run("collectUserAliasNames", func(t *testing.T) {
		// Test filtering AWS-managed aliases
		aliases := []types.AliasListEntry{
			{AliasName: aws.String("alias/user-key-1")},
			{AliasName: aws.String("alias/aws/s3")},
			{AliasName: aws.String("alias/user-key-2")},
			{AliasName: aws.String("alias/aws/rds")},
			{AliasName: aws.String("alias/my-custom-key")},
		}

		userAliases := awsEngine.collectUserAliasNames(aliases)
		assert.Len(t, userAliases, 3, "Should return only user-managed aliases")
		assert.Contains(t, userAliases, "user-key-1")
		assert.Contains(t, userAliases, "user-key-2")
		assert.Contains(t, userAliases, "my-custom-key")
		assert.NotContains(t, userAliases, "aws/s3")
		assert.NotContains(t, userAliases, "aws/rds")
	})
}
