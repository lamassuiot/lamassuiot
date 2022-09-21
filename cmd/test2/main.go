package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	mathRandom "math/rand"
	"net/url"
	"os"
	"time"

	"github.com/jakehl/goid"
	lamassucaclient "github.com/lamassuiot/lamassuiot/pkg/ca/client"
	"github.com/lamassuiot/lamassuiot/pkg/ca/common/api"
	lamassudmsclient "github.com/lamassuiot/lamassuiot/pkg/dms-manager/client"
	dmsApi "github.com/lamassuiot/lamassuiot/pkg/dms-manager/common/api"
	estClient "github.com/lamassuiot/lamassuiot/pkg/est/client"
	clientUtils "github.com/lamassuiot/lamassuiot/pkg/utils/client"
	commonApi "github.com/lamassuiot/lamassuiot/pkg/utils/common"
)

const (
	maxWorkers = 10
	devices    = 10000
)

type enrollJob struct {
	deviceID string
	aps      string
}

func main() {
	caClient, err := lamassucaclient.NewLamassuCAClient(clientUtils.BaseClientConfigurationuration{
		URL: &url.URL{
			Scheme: "https",
			Host:   "dev-lamassu.zpd.ikerlan.es:8087",
		},
		AuthMethod: clientUtils.AuthMethodNone,
		Insecure:   true,
	})
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	dmsClient, err := lamassudmsclient.NewLamassuDMSManagerClientConfig(clientUtils.BaseClientConfigurationuration{
		URL: &url.URL{
			Scheme: "https",
			Host:   "dev-lamassu.zpd.ikerlan.es:8085",
		},
		AuthMethod: clientUtils.AuthMethodNone,
		Insecure:   true,
	})
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	dmsName := fmt.Sprintf("test-dms-%s", goid.NewV4UUID())
	dmsOutput, err := dmsClient.CreateDMS(context.Background(), &dmsApi.CreateDMSInput{
		Subject: dmsApi.Subject{
			CommonName: dmsName,
		},
		KeyMetadata: dmsApi.KeyMetadata{
			KeyType: dmsApi.RSA,
			KeyBits: 2048,
		},
	})
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	pemKey, err := base64.StdEncoding.DecodeString(dmsOutput.PrivateKey.(string))
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	p, _ := pem.Decode(pemKey)
	dmsKey, err := x509.ParsePKCS1PrivateKey(p.Bytes)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	dmsUpdatedOutput, err := dmsClient.UpdateDMSStatus(context.Background(), &dmsApi.UpdateDMSStatusInput{
		Name:   dmsName,
		Status: dmsApi.DMSStatusApproved,
	})
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	casOutput, err := caClient.GetCAs(context.Background(), &api.GetCAsInput{
		CAType: api.CATypePKI,
		QueryParameters: commonApi.QueryParameters{
			Pagination: commonApi.PaginationOptions{
				Limit:  100,
				Offset: 0,
			},
		},
	})
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	authCAs := make([]string, 0)
	for _, ca := range casOutput.CAs {
		authCAs = append(authCAs, ca.CAName)
	}

	_, err = dmsClient.UpdateDMSAuthorizedCAs(context.Background(), &dmsApi.UpdateDMSAuthorizedCAsInput{
		Name:          dmsName,
		AuthorizedCAs: authCAs,
	})
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	estClientInstance, err := estClient.NewESTClient(
		nil,
		&url.URL{
			Scheme: "https",
			Host:   "dev-lamassu.zpd.ikerlan.es:8089",
		},
		dmsUpdatedOutput.X509Asset.Certificate,
		dmsKey,
		nil,
		true,
	)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	estCtx := context.Background()
	estCtx = context.WithValue(estCtx, estClient.WithXForwardedClientCertHeader, dmsUpdatedOutput.X509Asset.Certificate)

	jobs := make(chan enrollJob, devices)
	results := make(chan string)

	for i := 0; i < maxWorkers; i++ {
		go worker(estClientInstance, estCtx, jobs, results)
	}

	t0 := time.Now()
	for i := 0; i < devices; i++ {
		deviceID := fmt.Sprintf("device-%s", goid.NewV4UUID().String())
		idx := mathRandom.Intn(len(authCAs))

		jobs <- enrollJob{
			deviceID: deviceID,
			aps:      authCAs[idx],
		}
	}

	finishedDevices := 0
	for a := 1; a <= devices; a++ {
		<-results
		finishedDevices++

		if finishedDevices%(devices/100) == 0 {
			percentage := finishedDevices * 100 / devices
			tp := time.Since(t0)
			dexpected := time.Duration(tp.Nanoseconds() / int64(percentage) * int64(100-percentage))
			texpected := time.Now().Add(dexpected)
			fmt.Printf("%s %d%% - %d. Expected finish time: [%s] - %s\n", tp.String(), percentage, finishedDevices, dexpected.String(), texpected.String())
		}
	}

	t1 := time.Now()

	fmt.Printf("%d devices enrolled in %s with %d workers \n", devices, t1.Sub(t0), maxWorkers)
}

func worker(estclient estClient.ESTClient, ctx context.Context, jobs <-chan enrollJob, results chan<- string) {
	for j := range jobs {
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		template := x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName: j.deviceID,
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

		_, err = estclient.Enroll(ctx, j.aps, csr)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		results <- j.deviceID
	}
}
