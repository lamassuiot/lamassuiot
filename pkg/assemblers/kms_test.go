package assemblers

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"testing"

	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/pkg/services"
)

func TestCryptoEngines(t *testing.T) {
	serverTest, err := StartKMSServiceTestServer(t, false)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	kmsTest := serverTest.KMS

	var testcases = []struct {
		name        string
		resultCheck func(engines []*models.CryptoEngineProvider, err error) error
	}{
		{
			name: "OK/Got-2-Engines",
			resultCheck: func(engines []*models.CryptoEngineProvider, err error) error {
				if err != nil {
					return fmt.Errorf("should've got no error, but got one: %s", err)
				}

				if len(engines) != 2 {
					return fmt.Errorf("should've got two engines, but got %d", len(engines))
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

			err = tc.resultCheck(kmsTest.Service.GetCryptoEngineProvider(context.Background()))
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}

		})
	}
}

func TestKMSSignatureVerify(t *testing.T) {
	testServer, err := StartKMSServiceTestServer(t, false)
	if err != nil {
		t.Fatalf("could not create KMS test server: %s", err)
	}

	kmsTest := testServer.KMS
	key, err := kmsTest.Service.CreatePrivateKey(context.Background(), services.CreatePrivateKeyInput{
		KeyAlgorithm: models.KeyType(x509.RSA),
		KeySize:      2048,
	})
	if err != nil {
		t.Fatalf("could not create KMS test server: %s", err)
	}

	defaultKID := key.KeyID
	defaultEngine := key.EngineID

	t.Cleanup(kmsTest.AfterSuite)
	var testcases = []struct {
		name        string
		before      func(svc services.KMSService) error
		run         func(kmsSDK services.KMSService) (bool, error)
		resultCheck func(bool, error) error
	}{
		{
			name:   "OK/TestSignatureVerifyPlainMessage",
			before: func(svc services.KMSService) error { return nil },
			run: func(kmsSDK services.KMSService) (bool, error) {
				mess := "message tb signed"
				signature, err := kmsSDK.Sign(context.Background(), services.SignInput{
					EngineID:         defaultEngine,
					KeyID:            defaultKID,
					Message:          []byte(mess),
					MessageType:      models.Raw,
					SigningAlgorithm: "RSASSA_PKCS1_V1_5_SHA_256",
				})
				if err != nil {
					return false, err
				}

				//cas := []*models.CACertificate{}
				res, err := kmsSDK.Verify(context.Background(), services.VerifyInput{
					EngineID:         defaultEngine,
					KeyID:            defaultKID,
					Signature:        signature,
					SigningAlgorithm: "RSASSA_PKCS1_V1_5_SHA_256",
					MessageType:      models.Raw,
					Message:          []byte(mess),
				})
				return res, err
			},
			resultCheck: func(bol bool, err error) error {
				fmt.Println(bol)
				if !errors.Is(err, errs.ErrCAStatus) {
					return fmt.Errorf("got unexpected error: %s", err)
				}
				return nil
			},
		},
		// {
		// 	name:   "OK/TestSignatureVerifyHashMessage",
		// 	before: func(svc services.KMSService) error { return nil },
		// 	run: func(kmsSDK services.KMSService) (bool, error) {
		// 		h := sha256.New()
		// 		mess := "message tb signed"
		// 		h.Write([]byte(mess))
		// 		messH := h.Sum(nil)
		// 		messba64 := base64.StdEncoding.EncodeToString(messH)
		// 		sign, err := kmsSDK.Sign(context.Background(), services.SignInput{
		// 			EngineID:         defaultEngine,
		// 			KeyID:            defaultKID,
		// 			Message:          []byte(messba64),
		// 			MessageType:      models.Raw,
		// 			SigningAlgorithm: "RSASSA_PSS_SHA_256",
		// 		})
		// 		if err != nil {
		// 			return false, err
		// 		}

		// 		//cas := []*models.CACertificate{}
		// 		res, err := kmsSDK.Verify(context.Background(), services.VerifyInput{
		// 			EngineID:         defaultEngine,
		// 			KeyID:            defaultKID,
		// 			Signature:        sign,
		// 			SigningAlgorithm: "RSASSA_PSS_SHA_256",
		// 			MessageType:      models.Raw,
		// 			Message:          []byte(messba64),
		// 		})
		// 		return res, err
		// 	},
		// 	resultCheck: func(bol bool, err error) error {
		// 		fmt.Println(bol)
		// 		if !errors.Is(err, errs.ErrCAStatus) {
		// 			return fmt.Errorf("got unexpected error: %s", err)
		// 		}
		// 		return nil
		// 	},
		// },
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			//
			// err := postgres_test.BeforeEach()
			// fmt.Errorf("Error while running BeforeEach job: %s", err)

			err = kmsTest.BeforeEach()
			if err != nil {
				t.Fatalf("failed running 'BeforeEach' cleanup func in test case: %s", err)
			}

			err = tc.before(kmsTest.Service)
			if err != nil {
				t.Fatalf("failed running 'before' func in test case: %s", err)
			}

			err = tc.resultCheck(tc.run(kmsTest.HttpKMSSDK))
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}
		})
	}
}

func StartKMSServiceTestServer(t *testing.T, withEventBus bool) (*TestServer, error) {
	var err error
	eventBusConf := &TestEventBusConfig{
		config: config.EventBusEngine{
			Enabled: false,
		},
	}
	if withEventBus {
		eventBusConf, err = PrepareRabbitMQForTest()
		if err != nil {
			t.Fatalf("could not prepare RabbitMQ test server: %s", err)
		}
	}

	storageConfig, err := PreparePostgresForTest([]string{"ca"})
	if err != nil {
		t.Fatalf("could not prepare Postgres test server: %s", err)
	}

	cryptoConfig := PrepareCryptoEnginesForTest([]CryptoEngine{GOLANG, VAULT})
	testServer, err := AssembleServices(storageConfig, eventBusConf, cryptoConfig, []Service{KMS})
	if err != nil {
		t.Fatalf("could not assemble Server with HTTP server")
	}

	t.Cleanup(testServer.AfterSuite)

	return testServer, nil
}
