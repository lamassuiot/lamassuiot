//go:build windows
// +build windows

package cryptoengines

import (
	"fmt"

	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/sirupsen/logrus"
)

func NewPKCS11Engine(logger *logrus.Entry, conf config.PKCS11EngineConfig) (CryptoEngine, error) {
	return nil, fmt.Errorf("PKCS11 engine is not supported on Windows")
}
