package external_clients

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/url"

	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/sirupsen/logrus"
)

func GetCRLResponse(crlServerURL string, issuer *x509.Certificate, serverCertificate *x509.Certificate, verifyCRLResponse bool) (*x509.RevocationList, error) {
	httpRequest, err := http.NewRequest(http.MethodGet, crlServerURL, nil)
	if err != nil {
		return nil, fmt.Errorf("could not generate HTTP CRL request: %s", err)
	}

	crlURL, err := url.Parse(crlServerURL)
	if err != nil {
		return nil, fmt.Errorf("could not parse CRL server URL: %s", err)
	}

	httpRequest.Header.Add("host", crlURL.Host)

	httpClient := &http.Client{}
	if serverCertificate == nil {
		logrus.Warn("using insecure server validation in CRL request")
		httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
	} else {
		pool := chelpers.LoadSytemCACertPool()
		pool.AddCert(serverCertificate)

		httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: pool,
			},
		}
	}

	httpResponse, err := httpClient.Do(httpRequest)
	if err != nil {
		return nil, fmt.Errorf("could not do CRL request: %s", err)
	}

	defer httpResponse.Body.Close()
	output, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		return nil, fmt.Errorf("could not decode CRL response body: %s", err)
	}

	crl, err := x509.ParseRevocationList(output)
	if err != nil {
		return nil, fmt.Errorf("could not decode CRL response: %s", err)
	}

	if verifyCRLResponse {
		err := crl.CheckSignatureFrom(issuer)
		if err != nil {
			return nil, fmt.Errorf("could not validate CRL: %s", err)
		}
	}

	return crl, nil
}
