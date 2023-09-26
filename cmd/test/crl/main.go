package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"math/rand"
	"net/http"

	log "github.com/sirupsen/logrus"

	"github.com/lamassuiot/lamassuiot/pkg/v3/clients"
	"github.com/lamassuiot/lamassuiot/pkg/v3/helpers"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/lamassuiot/lamassuiot/pkg/v3/services"
)

var randPro = 56
var certsToIssue = 25

type DumpTransport struct {
	r http.RoundTripper
}

func (d *DumpTransport) RoundTrip(h *http.Request) (*http.Response, error) {
	//dump, _ := httputil.DumpRequestOut(h, true)
	//fmt.Printf("****REQUEST****\n%s\n", string(dump))
	resp, err := d.r.RoundTrip(h)
	if err != nil {
		return nil, err
	}
	//dump, _ = httputil.DumpResponse(resp, true)
	//fmt.Printf("****RESPONSE****\n%q\n****************\n\n", dump)
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

	caBoot, err := caCli.CreateCA(context.Background(), services.CreateCAInput{
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

	for i := 0; i < certsToIssue; i++ {
		key, _ := helpers.GenerateRSAKey(2048)
		csr, _ := helpers.GenerateCertificateRequest(models.Subject{CommonName: "myboot", Country: "ES"}, key)
		bootCrt, err := caCli.SignCertificate(context.Background(), services.SignCertificateInput{
			CAID:         caBoot.ID,
			CertRequest:  (*models.X509CertificateRequest)(csr),
			SignVerbatim: true,
		})
		if err != nil {
			log.Panic(err)
		}

		numb := rand.Intn(100-0) + 0
		if numb < randPro {
			_, err := caCli.UpdateCertificateStatus(context.Background(), services.UpdateCertificateStatusInput{
				SerialNumber: bootCrt.SerialNumber,
				NewStatus:    models.StatusRevoked,
			})
			if err != nil {
				panic(err)
			}
			log.Infof("Cert revoked with SerialNumber %s, CommonName %s", bootCrt.SerialNumber, bootCrt.Subject.CommonName)

		} else {
			log.Infof("Cert Boot with SerialNumber %s, CommonName %s", bootCrt.SerialNumber, bootCrt.Subject.CommonName)
		}

	}
}
