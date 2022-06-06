package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/jakehl/goid"
	caDTO "github.com/lamassuiot/lamassuiot/pkg/ca/common/dto"
	dmsDTO "github.com/lamassuiot/lamassuiot/pkg/dms-enroller/common/dto"
	estclient "github.com/lamassuiot/lamassuiot/pkg/est/client"
	"github.com/lamassuiot/lamassuiot/test/e2e/utils"
	client "github.com/lamassuiot/lamassuiot/test/e2e/utils/clients"
)

var domain = flag.String("domain", "", "domain")
var certPath = flag.String("cert", "", "ca certificate")
var dmsCertFile = "./certificates/dmsPer.crt"
var dmsKeyFile = "./certificates/dmsPer.key"
var caName = "test"
var deviceCsrFile = "./certificates/device.csr"
var deviceCertFile = "./certificates/device.crt"
var deviceKeyFile = "./certificates/device.key"
var deviceID = goid.NewV4UUID().String()

func TestCaCertsLamassuEstClient(t *testing.T) {
	os.Mkdir("./certificates", 0755)
	caName, _ = CreateCa(*domain, *certPath)
	_ = CreateDMS(*domain, *certPath, caName)
	serverCert, _ := utils.ReadCertPool(*certPath)
	dmsCert, _ := utils.ReadCert(dmsCertFile)
	dmsKey, _ := utils.ReadKey(dmsKeyFile)
	lamassuEstClient, _ := estclient.NewLamassuEstClient(*domain+"/api/devmanager", serverCert, dmsCert, dmsKey, nil)

	testCases := []struct {
		name string
		err  error
	}{
		{"CA Certs", nil},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {
			caCerts, err := lamassuEstClient.CACerts(context.Background())
			if err != nil {
				t.Fail()
			} else {
				if len(caCerts) == 0 {
					t.Errorf("Not receiving expected response")
				}
			}
		})
	}
}

func TestEnrollLamassuEstClient(t *testing.T) {
	os.Mkdir("./certificates", 0755)
	caName, _ = CreateCa(*domain, *certPath)
	_ = CreateDMS(*domain, *certPath, caName)
	serverCert, _ := utils.ReadCertPool(*certPath)
	dmsCert, _ := utils.ReadCert(dmsCertFile)
	dmsKey, _ := utils.ReadKey(dmsKeyFile)

	lamassuEstClient, _ := estclient.NewLamassuEstClient(*domain+"/api/devmanager", serverCert, dmsCert, dmsKey, nil)
	key, csr, _ := GenrateRandKey(log.Logger{})
	utils.InsertKey(deviceKeyFile, key)
	utils.InsertCsr(deviceCsrFile, csr.Raw)

	testCases := []struct {
		name string
		err  error
	}{
		{"Enroll", nil},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {
			devCert, err := lamassuEstClient.Enroll(context.Background(), caName, csr)
			if err != nil {
				t.Fail()
			} else {
				utils.InsertCert(deviceCertFile, devCert.Raw)
			}
		})
	}
}

func TestReenrollLamassuEstClient(t *testing.T) {
	os.Mkdir("./certificates", 0755)
	serverCert, _ := utils.ReadCertPool(*certPath)
	deviceCert, _ := utils.ReadCert(deviceCertFile)
	deviceKey, _ := utils.ReadKey(deviceKeyFile)
	lamassuEstClient, _ := estclient.NewLamassuEstClient(*domain+"/api/devmanager", serverCert, deviceCert, deviceKey, nil)
	csrContent, _ := ioutil.ReadFile(deviceCsrFile)
	cpb, _ := pem.Decode(csrContent)
	csr, _ := x509.ParseCertificateRequest(cpb.Bytes)

	testCases := []struct {
		name string
		err  error
	}{
		{"Reenroll", nil},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {
			devCert, err := lamassuEstClient.Reenroll(context.Background(), csr)
			if err != nil {
				t.Fail()
			} else {
				utils.InsertCert(deviceCertFile, devCert.Raw)
			}
		})
	}
}

func TestServerKeyGenLamassuEstClient(t *testing.T) {
	devClient, _ := client.LamassuDevClient(*certPath, *domain)
	serverCert, _ := utils.ReadCertPool(*certPath)
	dmsCert, _ := utils.ReadCert(dmsCertFile)
	dmsKey, _ := utils.ReadKey(dmsKeyFile)
	lamassuEstClient, _ := estclient.NewLamassuEstClient(*domain+"/api/devmanager", serverCert, dmsCert, dmsKey, nil)
	csrContent, _ := ioutil.ReadFile(deviceCsrFile)
	cpb, _ := pem.Decode(csrContent)
	csr, _ := x509.ParseCertificateRequest(cpb.Bytes)
	_ = devClient.RevokeDeviceCert(context.Background(), csr.Subject.CommonName, "")
	testCases := []struct {
		name string
		err  error
	}{
		{"Server Key Gen", nil},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {
			devCert, key, err := lamassuEstClient.ServerKeyGen(context.Background(), caName, csr)
			if err != nil {
				t.Fail()
			} else {
				utils.InsertCert(deviceCertFile, devCert.Raw)
				utils.InsertKey(deviceKeyFile, key)
			}
		})
	}
}
func TestGlobalsignEstClient_CaCerts(t *testing.T) {
	os.Chmod("./globalsign_cacerts.sh", 0755)
	cmd := &exec.Cmd{
		Path:   "./globalsign_cacerts.sh",
		Stdout: os.Stdout,
		Stdin:  os.Stdin,
	}
	testCases := []struct {
		name string
		err  error
	}{
		{"Global Sign Client", nil},
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

func TestGlobalsignEstClient_Enroll(t *testing.T) {
	os.Chmod("./globalsign_enroll.sh", 0755)
	cmd := &exec.Cmd{
		Path:   "./globalsign_enroll.sh",
		Stdout: os.Stdout,
		Stdin:  os.Stdin,
	}
	testCases := []struct {
		name string
		err  error
	}{
		{"Global Sign Client", nil},
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
func TestGlobalsignEstClient_Reenroll(t *testing.T) {
	os.Chmod("./globalsign_reenroll.sh", 0755)
	cmd := &exec.Cmd{
		Path:   "./globalsign_reenroll.sh",
		Stdout: os.Stdout,
		Stdin:  os.Stdin,
	}
	testCases := []struct {
		name string
		err  error
	}{
		{"Global Sign Client", nil},
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
func TestGlobalsignEstClient_ServerKeyGen(t *testing.T) {
	os.Chmod("./globalsign_serverkeygen.sh", 0755)
	cmd := &exec.Cmd{
		Path:   "./globalsign_serverkeygen.sh",
		Stdout: os.Stdout,
		Stdin:  os.Stdin,
	}
	testCases := []struct {
		name string
		err  error
	}{
		{"Global Sign Client", nil},
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
func TestCurl_CaCerts(t *testing.T) {
	os.Chmod("./curl_cacerts.sh", 0755)
	cmd := &exec.Cmd{
		Path:   "./curl_cacerts.sh",
		Stdout: os.Stdout,
		Stdin:  os.Stdin,
	}
	testCases := []struct {
		name string
		err  error
	}{
		{"Curl", nil},
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
func TestCurl_Enroll(t *testing.T) {
	os.Chmod("./curl_enroll.sh", 0755)
	cmd := &exec.Cmd{
		Path:   "./curl_enroll.sh",
		Stdout: os.Stdout,
		Stdin:  os.Stdin,
	}
	testCases := []struct {
		name string
		err  error
	}{
		{"Curl", nil},
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
func TestCurl_Reenroll(t *testing.T) {
	os.Chmod("./curl_reenroll.sh", 0755)
	cmd := &exec.Cmd{
		Path:   "./curl_reenroll.sh",
		Stdout: os.Stdout,
		Stdin:  os.Stdin,
	}
	testCases := []struct {
		name string
		err  error
	}{
		{"Curl", nil},
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
func TestCurl_ServerkeyGen(t *testing.T) {
	os.Chmod("./curl_serverkeygen.sh", 0755)
	cmd := &exec.Cmd{
		Path:   "./curl_serverkeygen.sh",
		Stdout: os.Stdout,
		Stdin:  os.Stdin,
	}
	testCases := []struct {
		name string
		err  error
	}{
		{"Curl", nil},
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

func CreateDMS(domain string, certPath string, caName string) error {

	dmsClient, err := client.LamassuDmsClient(certPath, domain)
	if err != nil {
		return err
	}
	dmsName := "Test-DMS"
	key, dms, err := dmsClient.CreateDMSForm(context.Background(), dmsDTO.Subject{CN: dmsName}, dmsDTO.PrivateKeyMetadata{KeyType: "RSA", KeyBits: 4096}, dmsName)
	if err != nil {
		return err
	}
	Privkey, _ := base64.StdEncoding.DecodeString(key)
	f, _ := os.Create(dmsKeyFile)
	f.Write(Privkey)
	f.Close()

	dms, err = dmsClient.UpdateDMSStatus(context.Background(), "APPROVED", dms.Id, []string{caName})
	if err != nil {
		return err
	}
	cert1, _ := base64.StdEncoding.DecodeString(dms.CerificateBase64)
	block, _ := pem.Decode([]byte(cert1))
	utils.InsertCert(dmsCertFile, block.Bytes)

	return nil
}

func CreateCa(domain string, certPath string) (string, error) {
	caClient, err := client.LamassuCaClient(certPath, domain)
	if err != nil {
		return "", err
	}
	caName := goid.NewV4UUID().String()
	ca, err := caClient.CreateCA(context.Background(), caDTO.Pki, caName, caDTO.PrivateKeyMetadata{KeyType: "RSA", KeyBits: 2048}, caDTO.Subject{CommonName: caName}, 365*time.Hour, 30*time.Hour)
	if err != nil {
		return "", err
	}
	return ca.Name, nil
}

func GenrateRandKey(logger log.Logger) ([]byte, *x509.CertificateRequest, error) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	privKey, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		return nil, nil, err
	}
	csr, err := GenerateCSR(rsaKey, "rsa")
	if err != nil {
		return nil, nil, err
	}
	return privKey, csr, nil

}

func GenerateCSR(key interface{}, Keytype string) (*x509.CertificateRequest, error) {

	subj := pkix.Name{
		Country:            []string{"ES"},
		Province:           []string{"Gipuzkoa"},
		Organization:       []string{"IKERLAN"},
		OrganizationalUnit: []string{"ZPD"},
		Locality:           []string{"Arrasate"},
		CommonName:         deviceID,
	}

	rawSubject := subj.ToRDNSequence()
	asn1Subj, _ := asn1.Marshal(rawSubject)
	var template x509.CertificateRequest
	if Keytype == "rsa" {
		template = x509.CertificateRequest{
			RawSubject:         asn1Subj,
			SignatureAlgorithm: x509.SHA512WithRSA,
		}
	} else {
		template = x509.CertificateRequest{
			RawSubject:         asn1Subj,
			SignatureAlgorithm: x509.ECDSAWithSHA512,
		}
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate request: %v", err)
	}

	csrNew, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate request: %v", err)
	}
	return csrNew, nil
}
