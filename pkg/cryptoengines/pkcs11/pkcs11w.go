//go:build windows
// +build windows

package pkcs11

import (
	"fmt"

	"github.com/lamassuiot/lamassuiot/v2/core/pkg/engines/cryptoengines"
	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/sirupsen/logrus"
)

func NewPKCS11Engine(logger *logrus.Entry, conf config.PKCS11EngineConfig) (cryptoengines.CryptoEngine, error) {
	return nil, fmt.Errorf("PKCS11 engine is not supported on Windows")
}
