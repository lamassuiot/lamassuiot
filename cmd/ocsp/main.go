package main

import (
	"crypto/x509"
	"encoding/pem"
	"net/url"
	"os"
	"strings"

	lamassucaclient "github.com/lamassuiot/lamassuiot/pkg/ca/client"
	"github.com/lamassuiot/lamassuiot/pkg/ocsp/server/api/service"
	"github.com/lamassuiot/lamassuiot/pkg/ocsp/server/api/transport"
	"github.com/lamassuiot/lamassuiot/pkg/ocsp/server/config"
	clientUtils "github.com/lamassuiot/lamassuiot/pkg/utils/client"
	"github.com/lamassuiot/lamassuiot/pkg/utils/server"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
)

func main() {
	config := config.NewOCSPConfig()
	if config.DebugMode {
		logrus.SetLevel(logrus.InfoLevel)
	}

	mainServer := server.NewServer(config)

	keyBytes, err := os.ReadFile(config.SignerKey)
	if err != nil {
		log.Fatal("Could not read key file: ", err)
	}

	block, _ := pem.Decode(keyBytes)
	rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatal("Could not parse key file: ", err)
	}

	certBytes, err := os.ReadFile(config.SignerCert)
	if err != nil {
		log.Fatal("Could not read cert file: ", err)
	}
	block, _ = pem.Decode(certBytes)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatal("Could not parse cert file: ", err)
	}

	var lamassuCAClient lamassucaclient.LamassuCAClient
	parsedLamassuCAURL, err := url.Parse(config.LamassuCAAddress)
	if err != nil {
		log.Fatal("Could not parse CA URL: ", err)
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
			log.Fatal("Could not create LamassuCA client: ", err)
		}
	} else {
		lamassuCAClient, err = lamassucaclient.NewLamassuCAClient(clientUtils.BaseClientConfigurationuration{
			URL:        parsedLamassuCAURL,
			AuthMethod: clientUtils.AuthMethodNone,
		})
		if err != nil {
			log.Fatal("Could not create LamassuCA client: ", err)
		}
	}

	s := service.NewOCSPService(lamassuCAClient, rsaKey, cert)

	mainServer.AddHttpHandler("/", transport.MakeHTTPHandler(s, false))

	mainServer.Run()
	forever := make(chan struct{})
	<-forever
}
