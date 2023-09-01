package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"time"

	"github.com/globalsign/est"
	"github.com/google/uuid"
	"github.com/lamassuiot/lamassuiot/pkg/v3/clients"
	"github.com/lamassuiot/lamassuiot/pkg/v3/helpers"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/lamassuiot/lamassuiot/pkg/v3/services"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ocsp"
)

type DumpTransport struct {
	r http.RoundTripper
}

func (d *DumpTransport) RoundTrip(h *http.Request) (*http.Response, error) {
	dump, _ := httputil.DumpRequestOut(h, true)
	fmt.Printf("****REQUEST****\n%s\n", string(dump))
	resp, err := d.r.RoundTrip(h)
	if err != nil {
		return nil, err
	}
	dump, _ = httputil.DumpResponse(resp, true)
	fmt.Printf("****RESPONSE****\n%q\n****************\n\n", dump)
	return resp, err
}

func main() {
	http.DefaultClient.Transport = &DumpTransport{
		r: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	caCli := clients.NewHttpCAClient(http.DefaultClient, "http://localhost:8085")

	issDur, _ := models.ParseDuration("10y")
	issTDur := models.TimeDuration(issDur)

	caDur, _ := models.ParseDuration("20y")
	caTDur := models.TimeDuration(caDur)

	caBoot, err := caCli.CreateCA(services.CreateCAInput{
		CAType:      models.CertificateTypeManaged,
		KeyMetadata: models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
		Subject:     models.Subject{CommonName: "test-ca"},
		IssuanceExpiration: models.Expiration{
			Type:     models.Duration,
			Duration: &issTDur,
		},
		CAExpiration: models.Expiration{
			Type:     models.Duration,
			Duration: &caTDur,
		},
	})
	if err != nil {
		log.Panic(err)
	}
	log.Infof("CA Boot with ID %s, CommonName %s, SerialNumber %s", caBoot.ID, caBoot.Subject.CommonName, caBoot.SerialNumber)

	caEnroll, err := caCli.CreateCA(services.CreateCAInput{
		CAType:      models.CertificateTypeManaged,
		KeyMetadata: models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
		Subject:     models.Subject{CommonName: "test-ca"},
		IssuanceExpiration: models.Expiration{
			Type:     models.Duration,
			Duration: &issTDur,
		},
		CAExpiration: models.Expiration{
			Type:     models.Duration,
			Duration: &caTDur,
		},
	})
	if err != nil {
		log.Panic(err)
	}

	log.Infof("CA Enroll with ID %s, CommonName %s, SerialNumber %s", caEnroll.ID, caEnroll.Subject.CommonName, caEnroll.SerialNumber)
	dmsCli := clients.NewHttpDMSManagerClient(http.DefaultClient, "https://localhost:8084")
	dms, err := dmsCli.CreateDMS(services.CreateDMSInput{
		ID:       fmt.Sprintf("dms-%s", uuid.NewString()),
		Name:     "My DMS",
		Metadata: map[string]string{},
		IdentityProfile: models.IdentityProfile{
			EnrollmentSettings: models.EnrollmentSettings{
				EnrollmentProtocol: models.EST,
				EnrollmentOptionsESTRFC7030: models.EnrollmentOptionsESTRFC7030{
					AuthMode: models.ESTAuthModeMutualTLS,
					AuthOptionsMTLS: struct {
						ValidationCAs []string "json:\"validation_cas\""
					}{
						ValidationCAs: []string{caBoot.ID},
					},
				},
				AuthorizedCA:       caEnroll.ID,
				AllowNewEnrollment: true,
				JustInTime:         true,
				DeviceProvisionSettings: models.DeviceProvisionSettings{
					Icon:      "aa",
					IconColor: "#255e32",
					Metadata: map[string]string{
						"dms-owner": "ai",
					},
					Tags: []string{"iot"},
				},
			},
			ReEnrollmentSettings: models.ReEnrollmentSettings{
				AllowedReenrollmentDelta: models.TimeDuration(time.Duration(1 * time.Hour)),
				AllowExpiredRenewal:      false,
			},
			CADistributionSettings: models.CADistributionSettings{},
		},
	})
	if err != nil {
		log.Panic(err)
	}

	log.Infof("DMS with ID %s", dms.ID)

	key, _ := helpers.GenerateRSAKey(2048)
	csr, _ := helpers.GenerateCertificateRequest(models.Subject{CommonName: "myboot", Country: "ES"}, key)
	bootCrt, err := caCli.SignCertificate(services.SignCertificateInput{
		CAID:         caBoot.ID,
		CertRequest:  (*models.X509CertificateRequest)(csr),
		SignVerbatim: true,
	})
	if err != nil {
		log.Panic(err)
	}

	log.Infof("Cert Boot with SerialNumber %s, CommonName %s", bootCrt.SerialNumber, bootCrt.Subject.CommonName)
	fmt.Println(bootCrt.Certificate.Subject.String())
	deviceCsr, _ := helpers.GenerateCertificateRequest(models.Subject{CommonName: fmt.Sprintf("my-device-%s", uuid.NewString()), Country: "ES"}, key)

	estCli := est.Client{
		Host:                  "localhost:8084",
		AdditionalPathSegment: dms.ID,
		InsecureSkipVerify:    true,
		PrivateKey:            key,
		Certificates: []*x509.Certificate{
			(*x509.Certificate)(bootCrt.Certificate),
		},
	}

	issuedCrt, err := estCli.Enroll(context.Background(), deviceCsr)
	if err != nil {
		log.Panic(err)
	}

	x509IssuedCert := models.X509Certificate(*issuedCrt)
	fmt.Println(x509IssuedCert.String())

	log.Infof("Issued Cert with SerialNumber %s, CommonName %s", helpers.SerialNumberToString(issuedCrt.SerialNumber), issuedCrt.Subject.CommonName)

	ocspRequBuffer, err := ocsp.CreateRequest(issuedCrt, (*x509.Certificate)(caEnroll.Certificate.Certificate), &ocsp.RequestOptions{
		Hash: crypto.SHA256,
	})
	if err != nil {
		log.Panic(err)
	}

	httpRequest, err := http.NewRequest("POST", "https://localhost:8081/v1/ocsp", bytes.NewBuffer(ocspRequBuffer))
	if err != nil {
		log.Panic(err)
	}

	httpRequest.Header.Add("Content-Type", "application/ocsp-request")
	httpRequest.Header.Add("Accept", "application/ocsp-response")
	httpClient := http.DefaultClient

	httpResponse, err := httpClient.Do(httpRequest)
	if err != nil {
		log.Panic(err)
	}

	defer httpResponse.Body.Close()
	output, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		log.Panic(err)
	}

	OCSPResponse, err := ocsp.ParseResponse(output, (*x509.Certificate)(caEnroll.Certificate.Certificate))
	if err != nil {
		log.Panic(err)
	}

	log.Infof("OCSP Response Status %d", OCSPResponse.Status)

	estCli.Certificates = []*x509.Certificate{issuedCrt}

	reenrolledCrt, err := estCli.Reenroll(context.Background(), deviceCsr)
	if err != nil {
		log.Panic(err)
	}

	x509ReenrolledCrt := models.X509Certificate(*reenrolledCrt)
	fmt.Println(x509ReenrolledCrt.String())
	log.Infof("ReEnrolled Cert with SerialNumber %s, CommonName %s", helpers.SerialNumberToString(x509ReenrolledCrt.SerialNumber), x509ReenrolledCrt.Subject.CommonName)

}
