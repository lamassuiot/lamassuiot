package main

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/lamassuiot/lamassuiot/pkg/v3/clients"
	"github.com/lamassuiot/lamassuiot/pkg/v3/helpers"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/lamassuiot/lamassuiot/pkg/v3/services"

	"github.com/haritzsaiz/est"
)

func main() {
	caDur := models.TimeDuration(time.Hour * 25)
	caIss := models.TimeDuration(time.Hour * 10)
	caClient := clients.NewHttpCAClient(http.DefaultClient, "http://localhost:8443/api/ca")
	testEnrollmentCA, err := caClient.CreateCA(context.Background(), services.CreateCAInput{
		KeyMetadata:        models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
		Subject:            models.Subject{CommonName: "TestEnrollmentCA"},
		CAExpiration:       models.Expiration{Type: models.Duration, Duration: &caDur},
		IssuanceExpiration: models.Expiration{Type: models.Duration, Duration: &caIss},
	})
	chk(err)

	fmt.Println(testEnrollmentCA.ID)

	testBootCA, err := caClient.CreateCA(context.Background(), services.CreateCAInput{
		KeyMetadata:        models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
		Subject:            models.Subject{CommonName: "testBootCA"},
		CAExpiration:       models.Expiration{Type: models.Duration, Duration: &caDur},
		IssuanceExpiration: models.Expiration{Type: models.Duration, Duration: &caIss},
	})
	chk(err)

	dmsClient := clients.NewHttpDMSManagerClient(http.DefaultClient, "http://localhost:8443/api/dmsmanager")
	dms, err := dmsClient.CreateDMS(services.CreateDMSInput{
		ID:       fmt.Sprintf("my-dms-%d", time.Now().Unix()),
		Name:     "My DMS",
		Metadata: map[string]any{},
		Settings: models.DMSSettings{
			EnrollmentSettings: models.EnrollmentSettings{
				EnrollmentProtocol: models.EST,
				EnrollmentOptionsESTRFC7030: models.EnrollmentOptionsESTRFC7030{
					AuthMode: models.ESTAuthModeClientCertificate,
					AuthOptionsMTLS: models.AuthOptionsClientCertificate{
						ValidationCAs:        []string{testBootCA.ID},
						ChainLevelValidation: -1,
					},
				},
				DeviceProvisionProfile: models.DeviceProvisionProfile{
					Icon:      "",
					IconColor: "",
					Metadata:  map[string]any{},
					Tags:      []string{"iot", "testdms", "cloud"},
				},
				EnrollmentCA:                testEnrollmentCA.ID,
				RegistrationMode:            models.JITP,
				EnableReplaceableEnrollment: true,
			},
			ReEnrollmentSettings: models.ReEnrollmentSettings{
				AdditionalValidationCAs:     []string{},
				ReEnrollmentDelta:           models.TimeDuration(time.Hour),
				EnableExpiredRenewal:        true,
				PreventiveReEnrollmentDelta: models.TimeDuration(time.Minute * 40),
				CriticalReEnrollmentDelta:   models.TimeDuration(time.Minute * 30),
			},
			CADistributionSettings: models.CADistributionSettings{
				IncludeLamassuSystemCA: true,
				IncludeEnrollmentCA:    true,
				ManagedCAs:             []string{},
			},
		},
	})
	chk(err)

	fmt.Println(dms.ID)

	bootKey, err := helpers.GenerateRSAKey(2048)
	chk(err)

	deviceCsr, err := helpers.GenerateCertificateRequest(models.Subject{CommonName: "device-1"}, bootKey)
	chk(err)

	sigedCrt, err := caClient.SignCertificate(context.Background(), services.SignCertificateInput{
		CAID:         testBootCA.ID,
		CertRequest:  (*models.X509CertificateRequest)(deviceCsr),
		SignVerbatim: true,
	})
	chk(err)

	fmt.Println(sigedCrt.SerialNumber)

	pem, err := base64.StdEncoding.DecodeString(sigedCrt.Certificate.String())
	chk(err)
	urlEncodedCrt := url.QueryEscape(string(pem))

	estHttpCli := est.NewHttpClient(est.HttpClientBuilder{
		PrivateKey:   bootKey,
		Certificates: []*x509.Certificate{(*x509.Certificate)(sigedCrt.Certificate)},
	})

	estCli := est.Client{
		HttpClient:            estHttpCli,
		HttpProtocol:          "http",
		AdditionalPathSegment: dms.ID,
		Host:                  "localhost:8443/api/dmsmanager",
		AdditionalHeaders: map[string]string{
			"x-forwarded-client-cert": fmt.Sprintf("Cert=%s", urlEncodedCrt),
		},
	}

	crt, err := estCli.Enroll(context.Background(), deviceCsr)
	chk(err)

	fmt.Println(crt.SerialNumber)
}

func chk(err error) {
	if err != nil {
		panic(err)
	}
}
