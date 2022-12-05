package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"net/url"
	"os"
	"sync/atomic"
	"time"

	"github.com/jakehl/goid"
	lamassucaclient "github.com/lamassuiot/lamassuiot/pkg/ca/client"
	"github.com/lamassuiot/lamassuiot/pkg/ca/common/api"
	lamassudmsclient "github.com/lamassuiot/lamassuiot/pkg/dms-manager/client"
	dmsApi "github.com/lamassuiot/lamassuiot/pkg/dms-manager/common/api"
	estClient "github.com/lamassuiot/lamassuiot/pkg/est/client"
	"github.com/lamassuiot/lamassuiot/pkg/utils"
	clientUtils "github.com/lamassuiot/lamassuiot/pkg/utils/client"
)

var failedOps uint64
var ops uint64

func main() {
	t0 := time.Now()

	var maxGoRoutines int
	flag.IntVar(&maxGoRoutines, "max-go-routines", 1, "Max Go Routines")

	var reenrolls int
	flag.IntVar(&reenrolls, "reenrolls", 150, "Reenrolls")

	var gatewayURL string
	flag.StringVar(&gatewayURL, "gateway-url", "https://istio.lamassu.zpd.ikerlan.es", "gateway URL")

	flag.Parse()

	fmt.Println("===== CA Stress test ====")
	fmt.Printf("max-go-routines: %d\n", maxGoRoutines)
	fmt.Printf("cas: %d\n", reenrolls)
	fmt.Printf("gatewayURL-url: %s\n", gatewayURL)

	if gatewayURL == "" {
		fmt.Printf("gateway URL cannot be empty. Exiting")
		os.Exit(1)
	}

	parsedGatewayURL, err := url.Parse(gatewayURL)
	if err != nil {
		fmt.Printf("Error while parsing gateway URL. Exiting: %s", err)
		os.Exit(1)
	}

	fmt.Println("\nstarting ...")

	var caClient lamassucaclient.LamassuCAClient
	caClient, err = lamassucaclient.NewLamassuCAClient(clientUtils.BaseClientConfigurationuration{
		URL: &url.URL{
			Scheme: parsedGatewayURL.Scheme,
			Host:   parsedGatewayURL.Host,
			Path:   "/api/ca",
		},
		AuthMethod: clientUtils.AuthMethodJWT,
		AuthMethodConfig: &clientUtils.JWTConfig{
			Username: "enroller",
			Password: "enroller",
			URL: &url.URL{
				Scheme: parsedGatewayURL.Scheme,
				Host:   "auth." + parsedGatewayURL.Host,
			},
			Insecure: true,
		},
		Insecure: true,
	})
	if err != nil {
		fmt.Printf("Could not create LamassuCA client. Exiting: %s", err)
		os.Exit(1)
	}

	time.Sleep(1 * time.Second)

	var dmsClient lamassudmsclient.LamassuDMSManagerClient
	dmsClient, err = lamassudmsclient.NewLamassuDMSManagerClientConfig(clientUtils.BaseClientConfigurationuration{
		URL: &url.URL{
			Scheme: parsedGatewayURL.Scheme,
			Host:   parsedGatewayURL.Host,
			Path:   "/api/dmsmanager",
		},
		AuthMethod: clientUtils.AuthMethodJWT,
		AuthMethodConfig: &clientUtils.JWTConfig{
			Username: "enroller",
			Password: "enroller",
			URL: &url.URL{
				Scheme: parsedGatewayURL.Scheme,
				Host:   "auth." + parsedGatewayURL.Host,
			},
			Insecure: true,
		},
		Insecure: true,
	})
	if err != nil {
		fmt.Printf("Could not create LamassuDMSManager client. Exiting: %s", err)
		os.Exit(1)
	}

	results := make(chan int, maxGoRoutines)

	for w := 0; w < maxGoRoutines; w++ {
		go worker(
			results,
			url.URL{
				Scheme: parsedGatewayURL.Scheme,
				Host:   parsedGatewayURL.Host,
				Path:   "api/devmanager",
			},
			reenrolls,
			caClient,
			dmsClient,
		)
	}

	for a := 1; a <= maxGoRoutines; a++ {
		<-results
	}

	t1 := time.Now()
	fmt.Println("failedOps:", failedOps)
	if ops > 0 {
		fmt.Printf("failedOps: %d%s\n", failedOps*100/uint64(ops), "%")
	}

	fmt.Println("Done in ", t1.Sub(t0).String())

}

func worker(results chan<- int, urlEstServer url.URL, reenrolls int, caClient lamassucaclient.LamassuCAClient, dmsClient lamassudmsclient.LamassuDMSManagerClient) {
	caName := fmt.Sprintf("CA-%s", goid.NewV4UUID().String())
	_, err := caClient.CreateCA(context.Background(), &api.CreateCAInput{
		CAType: api.CATypePKI,
		Subject: api.Subject{
			CommonName: caName,
		},
		KeyMetadata: api.KeyMetadata{
			KeyType: api.RSA,
			KeyBits: 4096,
		},
		CADuration:       time.Hour * 2,
		IssuanceDuration: time.Hour,
	})
	if err != nil {
		fmt.Println("GoRoutine could not create CA: ", err)
		os.Exit(1)
	}

	dmsName := fmt.Sprintf("dms-%s", goid.NewV4UUID().String())
	dmsInstance, err := dmsClient.CreateDMS(context.Background(), &dmsApi.CreateDMSInput{
		Subject: dmsApi.Subject{
			CommonName: dmsName,
		},
		KeyMetadata: dmsApi.KeyMetadata{
			KeyType: dmsApi.RSA,
			KeyBits: 2048,
		},
	})
	if err != nil {
		fmt.Println("GoRoutine could not create DMS: ", err)
		os.Exit(1)
	}

	time.Sleep(1 * time.Second)

	_, err = dmsClient.UpdateDMSStatus(context.Background(), &dmsApi.UpdateDMSStatusInput{
		Name:   dmsName,
		Status: dmsApi.DMSStatusApproved,
	})

	time.Sleep(1 * time.Second)

	if err != nil {
		fmt.Println("GoRoutine could not Update DMS Status: ", err)
		os.Exit(1)
	}

	authorizedDMSInstance, err := dmsClient.UpdateDMSAuthorizedCAs(context.Background(), &dmsApi.UpdateDMSAuthorizedCAsInput{
		Name: dmsName,
		AuthorizedCAs: []string{
			caName,
		},
	})
	if err != nil {
		fmt.Println("GoRoutine could not Update DMS Authz CAs: ", err)
		os.Exit(1)
	}

	bKey, _ := base64.StdEncoding.DecodeString(dmsInstance.PrivateKey.(string))
	fmt.Println(string(bKey))

	decoedPemKey, _ := pem.Decode(bKey)
	dmsKey, err := x509.ParsePKCS1PrivateKey(decoedPemKey.Bytes)
	if err != nil {
		fmt.Println("GoRoutine could not parse DMS Key: ", err)
		os.Exit(1)
	}

	time.Sleep(1 * time.Second)

	var devClient estClient.ESTClient
	devClient, err = estClient.NewESTClient(
		nil,
		&urlEstServer,
		authorizedDMSInstance.X509Asset.Certificate,
		dmsKey,
		nil,
		true,
	)

	if err != nil {
		fmt.Println("GoRoutine could not create EST Client for device: ", err)
		os.Exit(1)
	}

	devId := fmt.Sprintf("dev-%s", goid.NewV4UUID().String())
	key, csr := generateCertificateRequestAndKey(devId)

	crt, err := devClient.Enroll(context.Background(), caName, csr)
	if err != nil {
		fmt.Println("GoRoutine could not enroll device: ", err)
		os.Exit(1)
	}

	tmpFailed := 0
	for i := 0; i < reenrolls; i++ {
		time.Sleep(1 * time.Second)
		devClient, _ = estClient.NewESTClient(
			nil,
			&urlEstServer,
			crt,
			key,
			nil,
			true,
		)
		newCrt, err := devClient.Reenroll(context.Background(), csr)
		if err != nil {
			tmpFailed++
			fmt.Printf("Error while reenrolling [%s] iter [%d] used-serial [%s]: %s\n", devId, i, utils.InsertNth(utils.ToHexInt(crt.SerialNumber), 2), err)
			continue
		} else {
			crt = newCrt
			fmt.Printf("Success reenrolling [%s] iter [%d] new-serial [%s]\n", devId, i, utils.InsertNth(utils.ToHexInt(crt.SerialNumber), 2))
		}
	}

	atomic.AddUint64(&failedOps, uint64(tmpFailed))
	fmt.Printf("Done with [%s]. Failed ops [%d]\n", devId, tmpFailed)

	results <- 1
}

func generateCertificateRequestAndKey(commonName string) (*rsa.PrivateKey, *x509.CertificateRequest) {

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	csr := generateCertificateRequest(commonName, key)
	return key, csr
}

func generateCertificateRequest(commonName string, key *rsa.PrivateKey) *x509.CertificateRequest {

	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: commonName,
		},
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	if err != nil {
		panic(err)
	}

	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		panic(err)
	}

	return csr
}
