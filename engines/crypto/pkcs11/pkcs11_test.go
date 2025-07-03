package pkcs11

import (
	"os"
	"testing"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines"
	pconfig "github.com/lamassuiot/lamassuiot/engines/crypto/pkcs11/v3/config"
	"github.com/lamassuiot/lamassuiot/engines/crypto/pkcs11/v3/docker"
	"github.com/sirupsen/logrus"
)

func TestPKCS11CryptoEngine(t *testing.T) {
	table := []struct {
		name     string
		function func(t *testing.T, engine cryptoengines.CryptoEngine)
	}{
		{"CreateECDSAPrivateKey", cryptoengines.SharedTestCreateECDSAPrivateKey},
		{"CreateRSAPrivateKey", cryptoengines.SharedTestCreateRSAPrivateKey},
		{"SignRSA_PSS", cryptoengines.SharedTestRSAPSSSignature},
		{"SignRSA_PKCS1v1_5", cryptoengines.SharedTestRSAPKCS1v15Signature},
		{"SignECDSA", cryptoengines.SharedTestECDSASignature},
		// {"DeleteKey", cryptoengines.SharedTestDeleteKey}, TODO
		{"GetPrivateKeyByID", cryptoengines.SharedGetKey},
		{"GetPrivateKeyByIDNotFound", cryptoengines.SharedGetKeyNotFound},
		{"ListPrivateKeyIDs", cryptoengines.SharedListKeys},
		{"RenameKey", cryptoengines.SharedRenameKey},
	}

	beforeEach, err := setup(t)
	if err != nil {
		t.Fatal(err)
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			engine, err := beforeEach()
			if err != nil {
				t.Fatal(err)
			}

			// Run test
			tt.function(t, engine)
		})
	}
}

func setup(t *testing.T) (func() (cryptoengines.CryptoEngine, error), error) {
	os.Setenv("PKCS11_MODULE_PATH", "/usr/local/lib/libpkcs11-proxy.so")
	beforeEach, err := preparePKCS11CryptoEngine(t)
	if err != nil {
		t.Fatal(err)
	}

	return beforeEach, nil
}

func preparePKCS11CryptoEngine(t *testing.T) (func() (cryptoengines.CryptoEngine, error), error) {
	soPath, ok := os.LookupEnv("PKCS11_MODULE_PATH")
	if !ok {
		t.Skip("PKCS11_MODULE_PATH not set")
	}

	beforeEach, _, engineConf, err := docker.RunSoftHsmV2Docker(false, soPath)
	if err != nil {
		return nil, err
	}

	logger := logrus.New().WithField("test", "PKCS11")

	ceConfig := config.CryptoEngineConfigAdapter[pconfig.PKCS11Config]{
		ID:       "dockertest-pkcs11",
		Metadata: make(map[string]interface{}),
		Type:     config.PKCS11Provider,
		Config:   engineConf,
	}

	return func() (cryptoengines.CryptoEngine, error) {
		beforeEach()
		engine, err := NewPKCS11Engine(logger, ceConfig)
		if err != nil {
			return nil, err
		}

		return engine, nil
	}, nil
}
