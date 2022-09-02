package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"os"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	cryptoengines "github.com/lamassuiot/lamassuiot/pkg/ca/server/api/service/crypto-engines"
)

func main() {
	var logger log.Logger
	logger = log.NewLogfmtLogger(os.Stdout)
	logger = log.With(logger, "ts", log.DefaultTimestampUTC)

	engine, err := cryptoengines.NewHSMPEngine(logger, "/home/ikerlan/pkcs11-proxy/libpkcs11-proxy.so", "lamassuHSM", "1234")
	if err != nil {
		level.Error(logger).Log("msg", "Could not initialize HSM engine", "err", err)
		os.Exit(1)
	}

	hsm := engine.(*cryptoengines.HsmProviderContext)

	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	err = hsm.ImportRSAKeyPair("CA Ikerlan Production", key)
	fmt.Println(err)
}
