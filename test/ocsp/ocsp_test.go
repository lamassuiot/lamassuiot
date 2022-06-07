package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/jakehl/goid"
	caDTO "github.com/lamassuiot/lamassuiot/pkg/ca/common/dto"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/common/dto"
	dmsDTO "github.com/lamassuiot/lamassuiot/pkg/dms-enroller/common/dto"
	"github.com/lamassuiot/lamassuiot/pkg/ocsp/server/crypto/ocsp"
	"github.com/lamassuiot/lamassuiot/test/e2e/utils"
	client "github.com/lamassuiot/lamassuiot/test/e2e/utils/clients"
)

var domain = flag.String("domain", "", "domain")
var certPath = flag.String("cert", "", "ca certificate")
var ocspSignKey = flag.String("ocspSignKey", "", "ocspKey")
var oscpSignCert = flag.String("ocspSignCert", "", "ocspCert")
var dmsCertFile = "./dmsPer.crt"
var dmsKeyFile = "./dmsPer.key"

func TestOCSP_Get(t *testing.T) {
	var logger log.Logger
	{
		logger = log.NewJSONLogger(os.Stdout)
		logger = log.With(logger, "ts", log.DefaultTimestampUTC)
		logger = level.NewFilter(logger, level.AllowInfo())
		logger = log.With(logger, "caller", log.DefaultCaller)
	}

	devClient, _ := client.LamassuDevClient(*certPath, *domain)

	caName, caCert, _ := CreateCa(*domain, *certPath)
	dms, _ := CreateDMS(*domain, *certPath, caName)
	dmscert, _ := utils.ReadCert(dmsCertFile)
	dmskey, _ := utils.ReadKey(dmsKeyFile)
	servercert, _ := utils.ReadCertPool(*certPath)
	dev, _ := CreateDevice(*domain, *certPath, dms.Id)

	_, csr, _ := utils.GenrateRandKey(dev.Id)
	devCert, _ := devClient.Enroll(context.Background(), csr, caName, dmscert, dmskey, servercert, *domain+"/api/devmanager")

	ocspRequestBytes, err := ocsp.CreateRequest(devCert.Cert, caCert, &ocsp.RequestOptions{})
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	testCases := []struct {
		name             string
		ocspRequestBytes []byte
		err              error
	}{
		{"Correct", ocspRequestBytes, nil},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {
			encodedRequest := base64.StdEncoding.EncodeToString(ocspRequestBytes)
			reqURL := "https://" + *domain + "/api/ocsp/" + encodedRequest
			http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
			resp, err := http.Get(reqURL)
			if err != nil {
				fmt.Printf("err: %v\n", err)
				t.Fail()
			} else {
				if resp.StatusCode != http.StatusOK {
					t.Errorf("Not receiving expected response")
				}
				body, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					os.Exit(1)
				}
				resp.Body.Close()
				_, err = ocsp.ParseResponse(body, nil)
				if err != nil {
					t.Errorf("Not receiving expected response")
				}
			}
		})
	}
}

func TestOCSP_Post(t *testing.T) {
	var logger log.Logger
	{
		logger = log.NewJSONLogger(os.Stdout)
		logger = log.With(logger, "ts", log.DefaultTimestampUTC)
		logger = level.NewFilter(logger, level.AllowInfo())
		logger = log.With(logger, "caller", log.DefaultCaller)
	}
	devClient, _ := client.LamassuDevClient(*certPath, *domain)

	caName, caCert, _ := CreateCa(*domain, *certPath)
	dms, _ := CreateDMS(*domain, *certPath, caName)
	dmscert, _ := utils.ReadCert(dmsCertFile)
	dmskey, _ := utils.ReadKey(dmsKeyFile)
	servercert, _ := utils.ReadCertPool(*certPath)
	dev, _ := CreateDevice(*domain, *certPath, dms.Id)
	_, csr, _ := utils.GenrateRandKey(dev.Id)
	devCert, _ := devClient.Enroll(context.Background(), csr, caName, dmscert, dmskey, servercert, *domain+"/api/devmanager")

	ocspRequestBytes, err := ocsp.CreateRequest(devCert.Cert, caCert, &ocsp.RequestOptions{})
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	testCases := []struct {
		name             string
		ocspRequestBytes []byte
		err              error
	}{
		{"Correct", ocspRequestBytes, nil},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {
			reqURL := "https://" + *domain + "/api/ocsp/"
			http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
			resp, err := http.Post(reqURL, "application/ocsp-request", bytes.NewReader(ocspRequestBytes))
			if err != nil {
				fmt.Printf("err: %v\n", err)
				t.Fail()
			} else {
				if resp.StatusCode != http.StatusOK {
					t.Errorf("Not receiving expected response")
				}
				body, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					os.Exit(1)
				}
				resp.Body.Close()
				_, err = ocsp.ParseResponse(body, nil)
				if err != nil {
					t.Errorf("Not receiving expected response")
				}
			}
		})
	}
}
func TestCurl_Get(t *testing.T) {
	os.Chmod("./curl_Get.sh", 0755)
	cmd := &exec.Cmd{
		Path:   "./curl_Get.sh",
		Stdout: os.Stdout,
		Stdin:  os.Stdin,
	}
	testCases := []struct {
		name string
		err  error
	}{
		{"Get", nil},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {
			cmd.Start()
			err := cmd.Wait()
			if err != nil {
				t.Fail()
			}
		})
	}
}
func TestCurl_Post(t *testing.T) {
	os.Chmod("./curl_Get.sh", 0755)
	cmd := &exec.Cmd{
		Path:   "./curl_Get.sh",
		Stdout: os.Stdout,
		Stdin:  os.Stdin,
	}
	testCases := []struct {
		name string
		err  error
	}{
		{"Post", nil},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {
			cmd.Start()
			err := cmd.Wait()
			if err != nil {
				t.Fail()
			}
		})
	}
}
func CreateDMS(domain string, certPath string, caName string) (dmsDTO.DMS, error) {
	dms := dmsDTO.DMS{}
	dmsClient, err := client.LamassuDmsClient(certPath, domain)
	if err != nil {
		return dms, err
	}
	dmsName := goid.NewV4UUID().String()
	key, dms, err := dmsClient.CreateDMSForm(context.Background(), dmsDTO.Subject{CN: dmsName}, dmsDTO.PrivateKeyMetadata{KeyType: "RSA", KeyBits: 4096}, dmsName)
	if err != nil {
		return dms, err
	}
	Privkey, _ := base64.StdEncoding.DecodeString(key)
	f, _ := os.Create(dmsKeyFile)
	f.Write(Privkey)
	f.Close()

	dms, err = dmsClient.UpdateDMSStatus(context.Background(), "APPROVED", dms.Id, []string{caName})
	if err != nil {
		return dms, err
	}
	cert1, _ := base64.StdEncoding.DecodeString(dms.CerificateBase64)
	block, _ := pem.Decode([]byte(cert1))
	utils.InsertCert(dmsCertFile, block.Bytes)

	return dms, err
}

func CreateCa(domain string, certPath string) (string, *x509.Certificate, error) {
	caClient, err := client.LamassuCaClient(certPath, domain)
	caName := goid.NewV4UUID().String()
	ca, err := caClient.CreateCA(context.Background(), caDTO.Pki, caName, caDTO.PrivateKeyMetadata{KeyType: "RSA", KeyBits: 2048}, caDTO.Subject{CommonName: caName}, 365*time.Hour, 30*time.Hour)
	if err != nil {
		return "", nil, err
	}
	data, _ := base64.StdEncoding.DecodeString(ca.CertContent.CerificateBase64)
	block, _ := pem.Decode([]byte(data))
	cert, _ := x509.ParseCertificate(block.Bytes)
	return ca.Name, cert, nil

}

func CreateDevice(domain string, certPath string, dmsId string) (dto.Device, error) {
	devClient, err := client.LamassuDevClient(certPath, domain)
	if err != nil {
		return dto.Device{}, err
	}

	dev, err := devClient.CreateDevice(context.Background(), "testDevice", goid.NewV4UUID().String(), dmsId, "description", []string{"tag1"}, "", "")
	if err != nil {
		return dto.Device{}, err
	}
	return dev, nil
}
