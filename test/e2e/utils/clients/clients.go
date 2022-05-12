package client

import (
	"net/url"

	lamassuCAClient "github.com/lamassuiot/lamassuiot/pkg/ca/client"
	lamassuDevClient "github.com/lamassuiot/lamassuiot/pkg/device-manager/client"
	lamassuDMSClient "github.com/lamassuiot/lamassuiot/pkg/dms-enroller/client"
	"github.com/lamassuiot/lamassuiot/pkg/utils/client"
)

var lamassuGatewayURL = "dev-lamassu.zpd.ikerlan.es"
var caCert = "/home/ikerlan/lamassu/lamassuiot/test/e2e/apigw.crt"

func LamassuCaClient() (lamassuCAClient.LamassuCaClient, error) {
	return lamassuCAClient.NewLamassuCAClient(client.ClientConfiguration{
		URL: &url.URL{
			Scheme: "https",
			Host:   lamassuGatewayURL,
			Path:   "/api/ca/",
		},
		AuthMethod: client.JWT,
		AuthMethodConfig: &client.JWTConfig{
			Username: "enroller",
			Password: "enroller",
			URL: &url.URL{
				Scheme: "https",
				Host:   "auth." + lamassuGatewayURL,
			},
			CACertificate: caCert,
		},
		CACertificate: caCert,
	})

}

func LamassuDmsClient() (lamassuDMSClient.LamassuEnrollerClient, error) {
	return lamassuDMSClient.NewLamassuEnrollerClient(client.ClientConfiguration{
		URL: &url.URL{
			Scheme: "https",
			Host:   lamassuGatewayURL,
			Path:   "/api/dmsenroller/",
		},
		AuthMethod: client.JWT,
		AuthMethodConfig: &client.JWTConfig{
			Username: "enroller",
			Password: "enroller",
			URL: &url.URL{
				Scheme: "https",
				Host:   "auth." + lamassuGatewayURL,
			},
			CACertificate: caCert,
		},
		CACertificate: caCert,
	})
}

func LamassuDevClient() (lamassuDevClient.LamassuDevManagerClient, error) {
	return lamassuDevClient.NewLamassuDevManagerClient(client.ClientConfiguration{
		URL: &url.URL{
			Scheme: "https",
			Host:   lamassuGatewayURL,
			Path:   "/api/devmanager/",
		},
		AuthMethod: client.JWT,
		AuthMethodConfig: &client.JWTConfig{
			Username: "enroller",
			Password: "enroller",
			URL: &url.URL{
				Scheme: "https",
				Host:   "auth." + lamassuGatewayURL,
			},
			CACertificate: caCert,
		},
		CACertificate: caCert,
	})
}
