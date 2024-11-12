package external_clients

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/url"

	chelpers "github.com/lamassuiot/lamassuiot/v3/core/pkg/helpers"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ocsp"
)

func GetOCSPResponse(ocspServerURL string, certificate *x509.Certificate, issuer *x509.Certificate, serverCertificate *x509.Certificate, verifyOCSPResponse bool) (*ocsp.Response, error) {
	opts := &ocsp.RequestOptions{Hash: crypto.SHA1}
	buffer, err := ocsp.CreateRequest(certificate, issuer, opts)
	if err != nil {
		return nil, fmt.Errorf("could not generate OCSP request: %s", err)
	}

	httpRequest, err := http.NewRequest(http.MethodPost, ocspServerURL, bytes.NewBuffer(buffer))
	if err != nil {
		return nil, fmt.Errorf("could not generate HTTP OCSP request: %s", err)
	}

	ocspUrl, err := url.Parse(ocspServerURL)
	if err != nil {
		return nil, fmt.Errorf("could not parse OCSP server URL: %s", err)
	}

	httpRequest.Header.Add("Content-Type", "application/ocsp-request")
	httpRequest.Header.Add("Accept", "application/ocsp-response")
	httpRequest.Header.Add("host", ocspUrl.Host)

	httpClient := &http.Client{}
	if serverCertificate == nil {
		logrus.Warn("using insecure server validation in OCSP request")
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
		return nil, fmt.Errorf("could not DO OCSP request: %s", err)
	}

	defer httpResponse.Body.Close()
	output, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		return nil, fmt.Errorf("could not decode OCSP response: %s", err)
	}

	if verifyOCSPResponse {
		response, err := ocsp.ParseResponse(output, issuer)
		if err != nil {
			return nil, fmt.Errorf("could not parse OCSP response: %s", err)
		}

		return response, nil
	} else {
		response, err := ocsp.ParseResponse(output, nil)
		if err != nil {
			return nil, fmt.Errorf("could not parse OCSP response: %s", err)
		}

		return response, nil
	}
}
