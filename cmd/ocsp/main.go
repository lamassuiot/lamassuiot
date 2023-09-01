package main

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"strings"

	"github.com/lamassuiot/lamassuiot/pkg/ocsp/server/api/service"
	"github.com/lamassuiot/lamassuiot/pkg/ocsp/server/api/transport"
	"github.com/lamassuiot/lamassuiot/pkg/ocsp/server/config"
	"github.com/lamassuiot/lamassuiot/pkg/utils/server"
	"github.com/lamassuiot/lamassuiot/pkg/v3/clients"
	configV3 "github.com/lamassuiot/lamassuiot/pkg/v3/config"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
)

func main() {
	config := config.NewOCSPConfig()
	if config.DebugMode {
		logrus.SetLevel(logrus.InfoLevel)
	}

	mainServer := server.NewServer(config)

	var clientConf configV3.HTTPClient
	if strings.HasPrefix(config.LamassuCAAddress, "https") {
		clientConf = configV3.HTTPClient{
			AuthMode: configV3.MTLS,
			AuthMTLSOptions: configV3.AuthMTLSOptions{
				CertFile: config.CertFile,
				KeyFile:  config.KeyFile,
			},
			HTTPConnection: configV3.HTTPConnection{
				Protocol: configV3.HTTPS,
				BasePath: "",
				BasicConnection: configV3.BasicConnection{
					TLSConfig: configV3.TLSConfig{
						InsecureSkipVerify: true,
						CACertificateFile:  config.LamassuCACertFile,
					},
				},
			},
		}
	} else {
		clientConf = configV3.HTTPClient{
			AuthMode: configV3.NoAuth,
			HTTPConnection: configV3.HTTPConnection{
				Protocol: configV3.HTTP,
				BasePath: "",
				BasicConnection: configV3.BasicConnection{
					TLSConfig: configV3.TLSConfig{
						InsecureSkipVerify: true,
						CACertificateFile:  config.LamassuCACertFile,
					},
				},
			},
		}
	}

	caHttpClient, err := clients.BuildHTTPClient(clientConf, "CA")
	if err != nil {
		log.Fatal(err)
	}

	caClient := clients.NewhttpCAClient(caHttpClient, config.LamassuCAAddress)

	certBytes, err := os.ReadFile(config.SignerCert)
	if err != nil {
		log.Fatal("Could not read cert file: ", err)
	}
	block, _ := pem.Decode(certBytes)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatal("Could not parse cert file: ", err)
	}

	keyBytes, err := os.ReadFile(config.SignerKey)
	if err != nil {
		log.Fatal("Could not read key file: ", err)
	}

	block, _ = pem.Decode(keyBytes)

	rsaKey, rsaerr := x509.ParsePKCS1PrivateKey(block.Bytes)
	ecdsaKey, ecdsaerr := x509.ParseECPrivateKey(block.Bytes)
	var svc service.Service
	if rsaerr == nil {
		svc = service.NewOCSPService(caClient, rsaKey, cert)
		log.Trace("RSA TYPE")
	} else if ecdsaerr == nil {
		svc = service.NewOCSPService(caClient, ecdsaKey, cert)
		log.Trace("ECDSA TYPE")
	} else {
		log.Fatal("Could not parse key file: ", err)
	}

	mainServer.AddHttpHandler("/", transport.MakeHTTPHandler(svc, false))

	mainServer.Run()
	forever := make(chan struct{})
	<-forever
}
