package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/lamassuiot/lamassuiot/pkg/est/client"
)

func main() {
	estServerAddr := "dev.lamassu.io/api/devmanager"
	servercrt := "server.crt"
	dmscrt := "dms.crt"
	dmskey := "dms.key"
	devicecsr := "device.csr"
	ca_name := "Test-CA"
	caCert, err := ioutil.ReadFile(servercrt)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	certContent, err := ioutil.ReadFile(dmscrt)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	cpb, _ := pem.Decode(certContent)

	crt, err := x509.ParseCertificate(cpb.Bytes)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	certContent, err = ioutil.ReadFile(devicecsr)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	cpb, _ = pem.Decode(certContent)

	csr, err := x509.ParseCertificateRequest(cpb.Bytes)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	key, err := ioutil.ReadFile(dmskey)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	estClient, err := client.NewLamassuEstClient(estServerAddr, caCertPool, crt, key, nil)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	cert, err := estClient.Enroll(context.Background(), ca_name, csr)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Printf("cas: %s\n", cert)
}
