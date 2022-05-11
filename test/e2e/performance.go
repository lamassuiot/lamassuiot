package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/csv"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math"
	"net/url"
	"os"
	"time"

	"github.com/globalsign/pemfile"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/jakehl/goid"
	lamassuCAClient "github.com/lamassuiot/lamassuiot/pkg/ca/client"
	"github.com/lamassuiot/lamassuiot/pkg/ca/common/dto"
	caDTO "github.com/lamassuiot/lamassuiot/pkg/ca/common/dto"
	lamassuDevClient "github.com/lamassuiot/lamassuiot/pkg/device-manager/client"
	devdto "github.com/lamassuiot/lamassuiot/pkg/device-manager/common/dto"
	lamassuDmsClient "github.com/lamassuiot/lamassuiot/pkg/dms-enroller/client"
	dmsDTO "github.com/lamassuiot/lamassuiot/pkg/dms-enroller/common/dto"
	"github.com/lamassuiot/lamassuiot/pkg/utils/client"
)

var dmsCert = "/home/ikerlan/lamassu/lamassuiot/test/e2e/dmsPer.crt"
var dmsKey = "/home/ikerlan/lamassu/lamassuiot/test/e2e/dmsPer.key"
var deviceCert = "/home/ikerlan/lamassu/lamassuiot/test/e2e/device.crt"
var deviceKey = "/home/ikerlan/lamassu/lamassuiot/test/e2e/device.key"
var f, _ = os.Create("./GetCert.csv")
var f1, _ = os.Create("./GetIssuedCerts.csv")
var f2, _ = os.Create("./GetDevices.csv")
var f3, _ = os.Create("./GetDMSbyID.csv")
var f4, _ = os.Create("./GetDevicebyID.csv")
var f5, _ = os.Create("./GetCAs.csv")
var f6, _ = os.Create("./GetDeviceLogs.csv")
var f7, _ = os.Create("./GetDeviceCertHistory.csv")
var f8, _ = os.Create("./GetDmsCertHistory.csv")
var f9, _ = os.Create("./GetDmsLastIssuedCert.csv")
var f10, _ = os.Create("./GetDevicesbyDMS.csv")
var f11, _ = os.Create("./GetDMSs.csv")

func main() {
	fmt.Println("Cas: 0 - 100")
	err := CreateCAs(100)
	if err != nil {
		fmt.Println(err)
		return
	}
	err = DeleteDMS()
	if err != nil {
		fmt.Println(err)
		return
	}
	dmsID, dmsClient, err := CreateDMS()
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Scenario 1: 0 - 100")
	doScenario(100, 3, "Test-Performance", dmsID, dmsClient)

	fmt.Println("Scenario 2: 100 - 1000")
	doScenario(900, 3, "Test-Performance", dmsID, dmsClient)

	fmt.Println("Scenario 3: 1000 - 2500")
	doScenario(1500, 3, "Test-Performance", dmsID, dmsClient)

	fmt.Println("Scenario 4: 2500 - 5000")
	doScenario(2500, 3, "Test-Performance", dmsID, dmsClient)

	fmt.Println("Scenario 5: 5000 - 6000")
	doScenario(1000, 3, "Test-Performance", dmsID, dmsClient)

	fmt.Println("Scenario 6: 6000 - 8000")
	doScenario(2000, 3, "Test-Performance", dmsID, dmsClient)

	fmt.Println("Scenario 7: 8000 - 10000")
	doScenario(2000, 3, "Test-Performance", dmsID, dmsClient)

	fmt.Println("Scenario 8: 10000 - 20000")
	doScenario(10000, 3, "Test-Performance", dmsID, dmsClient)

	fmt.Println("Scenario 0")
	doScenario(0, 3, "Test-Performance", "", nil)
}

func doScenario(devicesToEnroll int, reenrollmentPerDevice int, caName string, dmsID string, dmsClient lamassuDmsClient.LamassuEnrollerClient) {
	var max, min float64
	max = 0
	min = 12
	var logger log.Logger
	{
		logger = log.NewJSONLogger(os.Stdout)
		logger = log.With(logger, "ts", log.DefaultTimestampUTC)
		logger = level.NewFilter(logger, level.AllowDebug())
		logger = log.With(logger, "caller", log.DefaultCaller)
	}
	devClient, err := lamassuDevClient.NewLamassuDevManagerClient(client.ClientConfiguration{
		URL: &url.URL{
			Scheme: "https",
			Host:   "dev-lamassu.zpd.ikerlan.es",
			Path:   "/api/devmanager/",
		},
		AuthMethod: client.JWT,
		AuthMethodConfig: &client.JWTConfig{
			Username: "enroller",
			Password: "enroller",
			URL: &url.URL{
				Scheme: "https",
				Host:   "auth." + "dev-lamassu.zpd.ikerlan.es",
			},
			CACertificate: "/home/ikerlan/lamassu/lamassuiot/test/e2e/apigw.crt",
		},
		CACertificate: "/home/ikerlan/lamassu/lamassuiot/test/e2e/apigw.crt",
	})

	for i := 0; i < devicesToEnroll; i++ {
		rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)

		subj := pkix.Name{
			Country:            []string{"ES"},
			Province:           []string{"Gipuzkoa"},
			Organization:       []string{"IKERLAN"},
			OrganizationalUnit: []string{"ZPD"},
			Locality:           []string{"Arrasate"},
			CommonName:         goid.NewV4UUID().String(),
		}

		rawSubject := subj.ToRDNSequence()
		asn1Subj, _ := asn1.Marshal(rawSubject)

		template := x509.CertificateRequest{
			RawSubject:         asn1Subj,
			SignatureAlgorithm: x509.SHA512WithRSA,
		}

		csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, rsaKey)
		if err != nil {
			fmt.Println(err)
			break
		}
		csr, err := x509.ParseCertificateRequest(csrBytes)
		if err != nil {
			fmt.Println(err)
			break
		}
		for k := 0; k < 10; k++ {
			before := time.Now().UnixNano()
			_, err = dmsClient.GetDMSbyID(context.Background(), dmsID)
			if err != nil {
				fmt.Println(err)
				break
			}
			after := time.Now().UnixNano()
			latency := float64((after - before)) / 1000000000
			max = math.Max(max, latency)
			min = math.Min(min, latency)
		}
		media := (max + min) / 2
		var data3 = [][]string{
			{dmsID, fmt.Sprint(max), fmt.Sprint(min), fmt.Sprint(media)},
		}
		err = WriteFile(f3, data3)
		if err != nil {
			return
		}

		serverKeyGen, err := devClient.ServerKeyGen(context.Background(), csr, caName, dmsCert, dmsKey, "/home/ikerlan/lamassu-compose-v2/tls-certificates/upstream/lamassu-device-manager/tls.crt", "dev-lamassu.zpd.ikerlan.es/api/devmanager")
		if err != nil {
			fmt.Println(err)
			return
		}
		for k := 0; k < 10; k++ {
			before := time.Now().UnixNano()
			_, err = devClient.GetDeviceById(context.Background(), serverKeyGen.Cert.Subject.CommonName)
			if err != nil {
				fmt.Println(err)
				break
			}
			after := time.Now().UnixNano()
			latency := float64((after - before)) / 1000000000
			max = math.Max(max, latency)
			min = math.Min(min, latency)
		}
		media = (max + min) / 2
		var data4 = [][]string{
			{dmsID, fmt.Sprint(max), fmt.Sprint(min), fmt.Sprint(media)},
		}
		err = WriteFile(f4, data4)
		if err != nil {
			return
		}

		dev, err := devClient.GetDeviceById(context.Background(), serverKeyGen.Cert.Subject.CommonName)
		if err != nil {
			fmt.Println(err)
			return
		}
		dev, err = devClient.UpdateDeviceById(context.Background(), "test-dev", dev.Id, dmsID, "updated device", []string{}, "", "")
		if err != nil {
			fmt.Println(err)
			return
		}
		b := pem.Block{Type: "PRIVATE KEY", Bytes: serverKeyGen.Key}
		keyPEM := pem.EncodeToMemory(&b)
		ioutil.WriteFile(deviceKey, keyPEM, 0777)

		privateKey, err := pemfile.ReadPrivateKey(deviceKey)
		if err != nil {
			fmt.Println(err)
			return
		}
		template = x509.CertificateRequest{
			RawSubject:         asn1Subj,
			SignatureAlgorithm: x509.ECDSAWithSHA512,
		}
		csrBytes, err = x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
		if err != nil {
			fmt.Println(err)
			break
		}
		csr, err = x509.ParseCertificateRequest(csrBytes)
		if err != nil {
			fmt.Println(err)
			break
		}
		b = pem.Block{Type: "CERTIFICATE", Bytes: serverKeyGen.Cert.Raw}
		certPEM := pem.EncodeToMemory(&b)
		ioutil.WriteFile(deviceCert, certPEM, 0777)
		for j := 0; j < reenrollmentPerDevice; j++ {
			reenroll, err := devClient.Reenroll(context.Background(), csr, caName, deviceCert, deviceKey, "/home/ikerlan/lamassu-compose-v2/tls-certificates/upstream/lamassu-device-manager/tls.crt", "dev-lamassu.zpd.ikerlan.es/api/devmanager")
			if err != nil {
				fmt.Println(err)
				return
			}
			b = pem.Block{Type: "CERTIFICATE", Bytes: reenroll.Cert.Raw}
			certPEM = pem.EncodeToMemory(&b)
			ioutil.WriteFile(deviceCert, certPEM, 0777)
		}

		for k := 0; k < 10; k++ {
			before := time.Now().UnixNano()
			_, err = devClient.GetDeviceCert(context.Background(), dev.Id)
			if err != nil {
				fmt.Println(err)
				return
			}
			after := time.Now().UnixNano()
			latency := float64((after - before)) / 1000000000
			max = math.Max(max, latency)
			min = math.Min(min, latency)
		}
		media = (max + min) / 2
		var data = [][]string{
			{dev.Id, fmt.Sprint(max), fmt.Sprint(min), fmt.Sprint(media)},
		}
		err = WriteFile(f, data)
		if err != nil {
			return
		}
		err = devClient.RevokeDeviceCert(context.Background(), dev.Id, "")
		if err != nil {
			fmt.Println(err)
			return
		}
		_, err = devClient.Enroll(context.Background(), csr, caName, dmsCert, dmsKey, "/home/ikerlan/lamassu-compose-v2/tls-certificates/upstream/lamassu-device-manager/tls.crt", "dev-lamassu.zpd.ikerlan.es/api/devmanager")
		if err != nil {
			fmt.Println(err)
			return
		}
		for k := 0; k < 10; k++ {
			before := time.Now().UnixNano()
			_, err = devClient.GetDeviceLogs(context.Background(), dev.Id)
			if err != nil {
				fmt.Println(err)
				return
			}
			after := time.Now().UnixNano()
			latency := float64((after - before)) / 1000000000
			max = math.Max(max, latency)
			min = math.Min(min, latency)
		}
		media = (max + min) / 2
		var data6 = [][]string{
			{dev.Id, fmt.Sprint(max), fmt.Sprint(min), fmt.Sprint(media)},
		}
		err = WriteFile(f6, data6)
		if err != nil {
			return
		}
		for k := 0; k < 10; k++ {
			before := time.Now().UnixNano()
			_, err = devClient.GetDeviceCertHistory(context.Background(), dev.Id)
			if err != nil {
				fmt.Println(err)
				return
			}
			after := time.Now().UnixNano()
			latency := float64((after - before)) / 1000000000
			max = math.Max(max, latency)
			min = math.Min(min, latency)
		}
		media = (max + min) / 2
		var data7 = [][]string{
			{dev.Id, fmt.Sprint(max), fmt.Sprint(min), fmt.Sprint(media)},
		}
		err = WriteFile(f7, data7)
		if err != nil {
			return
		}
	}
	var totaldmsCert int
	for k := 0; k < 10; k++ {
		before := time.Now().UnixNano()
		dmsCertHist, err := devClient.GetDmsCertHistoryThirtyDays(context.Background(), devdto.QueryParameters{Filter: "", Order: devdto.OrderOptions{Order: "DESC", Field: "id"}, Pagination: devdto.PaginationOptions{Page: 1, Offset: 15}})
		if err != nil {
			fmt.Println(err)
			return
		}
		after := time.Now().UnixNano()
		latency := float64((after - before)) / 1000000000
		max = math.Max(max, latency)
		min = math.Min(min, latency)
		totaldmsCert = len(dmsCertHist)
	}
	media := (max + min) / 2
	var data8 = [][]string{
		{fmt.Sprint(totaldmsCert), fmt.Sprint(max), fmt.Sprint(min), fmt.Sprint(media)},
	}
	err = WriteFile(f8, data8)
	if err != nil {
		return
	}
	var totaldmsCertLast int
	for k := 0; k < 10; k++ {
		before := time.Now().UnixNano()
		dmsCertLast, err := devClient.GetDmsLastIssuedCert(context.Background(), devdto.QueryParameters{Filter: "", Order: devdto.OrderOptions{Order: "DESC", Field: "id"}, Pagination: devdto.PaginationOptions{Page: 1, Offset: 15}})
		if err != nil {
			fmt.Println(err)
			return
		}
		after := time.Now().UnixNano()
		latency := float64((after - before)) / 1000000000
		max = math.Max(max, latency)
		min = math.Min(min, latency)
		totaldmsCertLast = len(dmsCertLast)
	}
	media = (max + min) / 2
	var data9 = [][]string{
		{fmt.Sprint(totaldmsCertLast), fmt.Sprint(max), fmt.Sprint(min), fmt.Sprint(media)},
	}
	err = WriteFile(f9, data9)
	if err != nil {
		return
	}
	var totaldevDMS int
	for k := 0; k < 10; k++ {
		before := time.Now().UnixNano()
		devices, err := devClient.GetDevicesByDMS(context.Background(), dmsID, devdto.QueryParameters{Filter: "", Order: devdto.OrderOptions{Order: "DESC", Field: "id"}, Pagination: devdto.PaginationOptions{Page: 1, Offset: 15}})
		if err != nil {
			fmt.Println(err)
			return
		}
		after := time.Now().UnixNano()
		latency := float64((after - before)) / 1000000000
		max = math.Max(max, latency)
		min = math.Min(min, latency)
		totaldevDMS = len(devices)
	}
	media = (max + min) / 2
	var data10 = [][]string{
		{fmt.Sprint(totaldevDMS), fmt.Sprint(max), fmt.Sprint(min), fmt.Sprint(media)},
	}
	err = WriteFile(f10, data10)
	if err != nil {
		return
	}
	var totalDMS int
	for k := 0; k < 10; k++ {
		before := time.Now().UnixNano()
		dmss, err := dmsClient.GetDMSs(context.Background())
		if err != nil {
			fmt.Println(err)
			return
		}
		after := time.Now().UnixNano()
		latency := float64((after - before)) / 1000000000
		max = math.Max(max, latency)
		min = math.Min(min, latency)
		totalDMS = len(dmss)
	}
	media = (max + min) / 2
	var data11 = [][]string{
		{fmt.Sprint(totalDMS), fmt.Sprint(max), fmt.Sprint(min), fmt.Sprint(media)},
	}
	err = WriteFile(f11, data11)
	if err != nil {
		return
	}
	caClient, err := lamassuCAClient.NewLamassuCAClient(client.ClientConfiguration{
		URL: &url.URL{
			Scheme: "https",
			Host:   "dev-lamassu.zpd.ikerlan.es",
			Path:   "/api/ca/",
		},
		AuthMethod: client.JWT,
		AuthMethodConfig: &client.JWTConfig{
			Username: "enroller",
			Password: "enroller",
			URL: &url.URL{
				Scheme: "https",
				Host:   "auth." + "dev-lamassu.zpd.ikerlan.es",
			},
			CACertificate: "/home/ikerlan/lamassu/lamassuiot/test/e2e/apigw.crt",
		},
		CACertificate: "/home/ikerlan/lamassu/lamassuiot/test/e2e/apigw.crt",
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	before := time.Now().UnixNano()
	_, total, err := devClient.GetDevices(context.Background(), devdto.QueryParameters{Filter: "", Order: devdto.OrderOptions{Order: "DESC", Field: "id"}, Pagination: devdto.PaginationOptions{Page: 1, Offset: 15}})
	if err != nil {
		after := time.Now().UnixNano()
		str := fmt.Sprintln("latency:", float64((after-before))/1000000000, "s")
		fmt.Println(err)
		fmt.Println(str)
		return
	}
	after := time.Now().UnixNano()
	var data1 = [][]string{
		{fmt.Sprint(total), fmt.Sprint(float64((after - before)) / 1000000000)},
	}
	err = WriteFile(f2, data1)
	if err != nil {
		return
	}

	before = time.Now().UnixNano()
	certs, err := caClient.GetIssuedCerts(context.Background(), dto.Pki, caName, "{1,50}")
	if err != nil {
		after := time.Now().UnixNano()
		str := fmt.Sprintln("latency:", float64((after-before))/1000000000, "s")
		fmt.Println(err)
		fmt.Println(str)
		return
	}
	after = time.Now().UnixNano()
	var data2 = [][]string{
		{fmt.Sprint(certs.TotalCerts), fmt.Sprint(float64((after - before)) / 1000000000)},
	}
	err = WriteFile(f1, data2)
	if err != nil {
		return
	}

}
func CreateDMS() (string, lamassuDmsClient.LamassuEnrollerClient, error) {
	dmsClient, err := lamassuDmsClient.NewLamassuEnrollerClient(client.ClientConfiguration{
		URL: &url.URL{
			Scheme: "https",
			Host:   "dev-lamassu.zpd.ikerlan.es",
			Path:   "/api/devmanager/",
		},
		AuthMethod: client.JWT,
		AuthMethodConfig: &client.JWTConfig{
			Username: "enroller",
			Password: "enroller",
			URL: &url.URL{
				Scheme: "https",
				Host:   "auth." + "dev-lamassu.zpd.ikerlan.es",
			},
			CACertificate: "/home/ikerlan/lamassu/lamassuiot/test/e2e/apigw.crt",
		},
		CACertificate: "/home/ikerlan/lamassu/lamassuiot/test/e2e/apigw.crt",
	})
	key, dms, err := dmsClient.CreateDMSForm(context.Background(), dmsDTO.Subject{CN: "test-dms"}, dmsDTO.PrivateKeyMetadata{KeyType: "RSA", KeyBits: 4096}, "test-dms")
	if err != nil {
		fmt.Println(err)
		return "", nil, err
	}
	Privkey, _ := base64.StdEncoding.DecodeString(key)
	err = ioutil.WriteFile(dmsKey, Privkey, 0644)

	dms, err = dmsClient.UpdateDMSStatus(context.Background(), "APPROVED", dms.Id, []string{"Test-Performance"})
	if err != nil {
		fmt.Println(err)

		return "", nil, err
	}
	cert1, _ := base64.StdEncoding.DecodeString(dms.CerificateBase64)
	block, _ := pem.Decode([]byte(cert1))
	b := pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes}
	certPEM := pem.EncodeToMemory(&b)
	ioutil.WriteFile(dmsCert, certPEM, 0777)

	return dms.Id, dmsClient, nil
}
func WriteFile(file *os.File, data [][]string) error {
	writer := csv.NewWriter(file)
	err := writer.WriteAll(data)
	if err != nil {
		fmt.Println(err)
		return err
	}
	return nil
}
func CreateCAs(caNumber int) error {
	caClient, err := lamassuCAClient.NewLamassuCAClient(client.ClientConfiguration{
		URL: &url.URL{
			Scheme: "https",
			Host:   "dev-lamassu.zpd.ikerlan.es",
			Path:   "/api/ca/",
		},
		AuthMethod: client.JWT,
		AuthMethodConfig: &client.JWTConfig{
			Username: "enroller",
			Password: "enroller",
			URL: &url.URL{
				Scheme: "https",
				Host:   "auth." + "dev-lamassu.zpd.ikerlan.es",
			},
			CACertificate: "/home/ikerlan/lamassu/lamassuiot/test/e2e/apigw.crt",
		},
		CACertificate: "/home/ikerlan/lamassu/lamassuiot/test/e2e/apigw.crt",
	})
	var createCa caDTO.Cert
	for i := 0; i < caNumber; i++ {
		var max, min float64
		var totalCas int
		max = 0
		min = 12
		caName := goid.NewV4UUID().String()
		createCa, err = caClient.CreateCA(context.Background(), caDTO.Pki, caName, caDTO.PrivateKeyMetadata{KeyType: "rsa", KeyBits: 2048}, caDTO.Subject{CN: caName}, 365*time.Hour, 30*time.Hour)
		if err != nil {
			fmt.Println(err)
			return err
		}
		for k := 0; k < 10; k++ {
			before := time.Now().UnixNano()
			ca, err := caClient.GetCAs(context.Background(), caDTO.Pki)
			if err != nil {
				fmt.Println(err)
				return err
			}
			after := time.Now().UnixNano()
			latency := float64((after - before)) / 1000000000
			max = math.Max(max, latency)
			min = math.Min(min, latency)
			totalCas = len(ca)
		}
		media := (max + min) / 2
		var data5 = [][]string{
			{fmt.Sprint(totalCas), fmt.Sprint(max), fmt.Sprint(min), fmt.Sprint(media)},
		}
		err = WriteFile(f5, data5)
		if err != nil {
			return err
		}

	}
	err = caClient.DeleteCA(context.Background(), caDTO.Pki, createCa.Name)
	if err != nil {
		return err
	}
	return nil

}
func DeleteDMS() error {
	dmsClient, _ := lamassuDmsClient.NewLamassuEnrollerClient(client.ClientConfiguration{
		URL: &url.URL{
			Scheme: "https",
			Host:   "dev-lamassu.zpd.ikerlan.es",
			Path:   "/api/devmanager/",
		},
		AuthMethod: client.JWT,
		AuthMethodConfig: &client.JWTConfig{
			Username: "enroller",
			Password: "enroller",
			URL: &url.URL{
				Scheme: "https",
				Host:   "auth." + "dev-lamassu.zpd.ikerlan.es",
			},
			CACertificate: "/home/ikerlan/lamassu/lamassuiot/test/e2e/apigw.crt",
		},
		CACertificate: "/home/ikerlan/lamassu/lamassuiot/test/e2e/apigw.crt",
	})
	_, dms, err := dmsClient.CreateDMSForm(context.Background(), dmsDTO.Subject{CN: "test-dms-Delete"}, dmsDTO.PrivateKeyMetadata{KeyType: "RSA", KeyBits: 4096}, "test-dms-Delete")
	if err != nil {
		fmt.Println(err)
		return err
	}

	dms, err = dmsClient.UpdateDMSStatus(context.Background(), "APPROVED", dms.Id, []string{"Test-Performance"})
	if err != nil {
		fmt.Println(err)
		return err
	}
	err = dmsClient.DeleteDMS(context.Background(), dms.Id)
	if err != nil {
		fmt.Println(err)
		return err
	}
	return nil
}
