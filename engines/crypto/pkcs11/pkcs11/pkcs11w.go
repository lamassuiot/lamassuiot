//go:build windows
// +build windows

package pkcs11

import (
	"fmt"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines"
	"github.com/sirupsen/logrus"
)

func NewPKCS11Engine(logger *logrus.Entry, conf config.CryptoEngineConfigAdapter[PKCS11Config]) (cryptoengines.CryptoEngine, error) {
	return nil, fmt.Errorf("PKCS11 engine is not supported on Windows")
}
