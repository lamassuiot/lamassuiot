package pkcs11

import (
	"os"
	"testing"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines"
	pconfig "github.com/lamassuiot/lamassuiot/engines/crypto/pkcs11/v3/config"
	"github.com/lamassuiot/lamassuiot/engines/crypto/pkcs11/v3/docker"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestPKCS11CryptoEngine(t *testing.T) {
	engine := preparePKCS11CryptoEngine(t)

	table := []struct {
		name     string
		function func(t *testing.T, engine cryptoengines.CryptoEngine)
	}{
		{"CreateECDSAPrivateKey", cryptoengines.SharedTestCreateECDSAPrivateKey},
		{"CreateRSAPrivateKey", cryptoengines.SharedTestCreateRSAPrivateKey},
		// {"DeleteKey", cryptoengines.SharedTestDeleteKey}, TODO
		{"GetPrivateKeyByID", cryptoengines.SharedGetKey},
		{"GetPrivateKeyByIDNotFound", cryptoengines.SharedGetKeyNotFound},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			tt.function(t, engine)
		})
	}

}

func preparePKCS11CryptoEngine(t *testing.T) cryptoengines.CryptoEngine {
	soPath, ok := os.LookupEnv("PKCS11_MODULE_PATH")
	if !ok {
		t.Skip("PKCS11_MODULE_PATH not set")
	}

	vPkcs11, engineConf, err := docker.RunSoftHsmV2Docker(soPath)
	t.Cleanup(func() { _ = vPkcs11() })
	assert.NoError(t, err)

	logger := logrus.New().WithField("test", "PKCS11")

	ceConfig := config.CryptoEngineConfigAdapter[pconfig.PKCS11Config]{
		ID:       "dockertest-pkcs11",
		Metadata: make(map[string]interface{}),
		Type:     config.PKCS11Provider,
		Config:   *engineConf,
	}

	engine, err := NewPKCS11Engine(logger, ceConfig)
	assert.NoError(t, err)

	return engine
}
