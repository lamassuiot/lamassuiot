package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	lamassucaclient "github.com/lamassuiot/lamassuiot/pkg/ca/client"
	"github.com/lamassuiot/lamassuiot/pkg/ocsp/server/api/service"
	"github.com/lamassuiot/lamassuiot/pkg/ocsp/server/api/transport"
	"github.com/lamassuiot/lamassuiot/pkg/ocsp/server/config"
	clientUtils "github.com/lamassuiot/lamassuiot/pkg/utils/client"
	"github.com/lamassuiot/lamassuiot/pkg/utils/server"
)

func main() {
	config := config.NewOCSPConfig()
	mainServer := server.NewServer(config)

	keyBytes, err := os.ReadFile(config.SignerKey)
	if err != nil {
		level.Error(mainServer.Logger).Log("msg", "Could not read key file", "err", err)
		os.Exit(1)
	}

	block, _ := pem.Decode(keyBytes)
	rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		level.Error(mainServer.Logger).Log("msg", "Could not parse key file", "err", err)
		os.Exit(1)
	}

	certBytes, err := os.ReadFile(config.SignerCert)
	if err != nil {
		level.Error(mainServer.Logger).Log("msg", "Could not read cert file", "err", err)
		os.Exit(1)
	}
	block, _ = pem.Decode(certBytes)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		level.Error(mainServer.Logger).Log("msg", "Could not parse cert file", "err", err)
		os.Exit(1)
	}

	var lamassuCAClient lamassucaclient.LamassuCAClient
	parsedLamassuCAURL, err := url.Parse(config.LamassuCAAddress)
	if err != nil {
		level.Error(mainServer.Logger).Log("msg", "Could not parse CA URL", "err", err)
		os.Exit(1)
	}

	if strings.HasPrefix(config.LamassuCAAddress, "https") {
		lamassuCAClient, err = lamassucaclient.NewLamassuCAClient(clientUtils.BaseClientConfigurationuration{
			URL:        parsedLamassuCAURL,
			AuthMethod: clientUtils.AuthMethodMutualTLS,
			AuthMethodConfig: &clientUtils.MutualTLSConfig{
				ClientCert: config.CertFile,
				ClientKey:  config.KeyFile,
			},
			CACertificate: config.LamassuCACertFile,
		})
		if err != nil {
			level.Error(mainServer.Logger).Log("msg", "Could not create LamassuCA client", "err", err)
			os.Exit(1)
		}
	} else {
		lamassuCAClient, err = lamassucaclient.NewLamassuCAClient(clientUtils.BaseClientConfigurationuration{
			URL:        parsedLamassuCAURL,
			AuthMethod: clientUtils.AuthMethodNone,
		})
		if err != nil {
			level.Error(mainServer.Logger).Log("msg", "Could not create LamassuCA client", "err", err)
			os.Exit(1)
		}
	}

	s := service.NewOCSPService(lamassuCAClient, rsaKey, cert)

	mainServer.AddHttpHandler("/", transport.MakeHTTPHandler(s, log.With(mainServer.Logger, "component", "HTTPS"), false))

	errs := make(chan error)
	go func() {
		c := make(chan os.Signal)
		signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
		errs <- fmt.Errorf("%s", <-c)
	}()

	mainServer.Run(errs)
	level.Info(mainServer.Logger).Log("exit", <-errs)
}
