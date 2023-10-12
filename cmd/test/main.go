package main

import (
	"context"
	"crypto/x509"
	"net/http"
	"time"

	"github.com/lamassuiot/lamassuiot/pkg/v3/clients"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/lamassuiot/lamassuiot/pkg/v3/services"
)

func main() {
	caDur := models.TimeDuration(time.Hour * 25)
	caIss := models.TimeDuration(time.Hour * 10)
	caClient := clients.NewHttpCAClient(http.DefaultClient, "http://lamassu.zpd.ikerlan.es:8085")
	_, err := caClient.CreateCA(context.Background(), services.CreateCAInput{
		KeyMetadata:        models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
		Subject:            models.Subject{CommonName: "Test"},
		CAExpiration:       models.Expiration{Type: models.Duration, Duration: &caDur},
		IssuanceExpiration: models.Expiration{Type: models.Duration, Duration: &caIss},
	})

	if err != nil {
		panic(err)
	}
}
