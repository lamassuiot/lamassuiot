package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/lamassuiot/lamassuiot/pkg/ocsp/server/crypto/ocsp"
)

func main() {
	// sendOCSPRequest("http://localhost:9098", ,)
	caPEM, err := ioutil.ReadFile("ca.crt")
	if err != nil {
		fmt.Println("Could not load CA certificate")
		os.Exit(1)
	}
	caPemBlock, _ := pem.Decode(caPEM)
	ca, err := x509.ParseCertificate(caPemBlock.Bytes)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	devicePEM, err := ioutil.ReadFile("device.crt")
	if err != nil {
		fmt.Println("Could not load Device certificate")
		os.Exit(1)
	}
	devicePemBlock, _ := pem.Decode(devicePEM)
	device, err := x509.ParseCertificate(devicePemBlock.Bytes)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	ocspRequestBytes, err := ocsp.CreateRequest(device, ca, &ocsp.RequestOptions{})
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	encodedRequest := base64.StdEncoding.EncodeToString(ocspRequestBytes)
	fmt.Println(encodedRequest)

	server := "http://localhost:9098"
	reqURL := server + "/" + encodedRequest

	resp, err := http.Get(reqURL)

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if resp.StatusCode != http.StatusOK {
		os.Exit(1)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		os.Exit(1)
	}
	resp.Body.Close()

	ocspResponse, err := ocsp.ParseResponse(body, nil)
	if err != nil {
		fmt.Println("Could not parse OCSP response ", err)
		os.Exit(1)
	}

	fmt.Println(ocspResponse.Status == ocsp.Good)
	fmt.Println(ocspResponse.Status == ocsp.Revoked)
	fmt.Println(ocspResponse.RevocationReason)
	fmt.Println(ocspResponse.RevokedAt)
}
