package external_clients

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"time"

	chelpers "github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ocsp"
)

func GetOCSPResponseGet(ocspServerURL string, certificate *x509.Certificate, issuer *x509.Certificate, serverCertificate *x509.Certificate, verifyOCSPResponse bool) (*ocsp.Response, error) {
	return getOCSPResponse(http.MethodGet, ocspServerURL, certificate, issuer, serverCertificate, verifyOCSPResponse)
}

func GetOCSPResponsePost(ocspServerURL string, certificate *x509.Certificate, issuer *x509.Certificate, serverCertificate *x509.Certificate, verifyOCSPResponse bool) (*ocsp.Response, error) {
	return getOCSPResponse(http.MethodPost, ocspServerURL, certificate, issuer, serverCertificate, verifyOCSPResponse)
}

func getOCSPResponse(method string, ocspServerURL string, certificate *x509.Certificate, issuer *x509.Certificate, serverCertificate *x509.Certificate, verifyOCSPResponse bool) (*ocsp.Response, error) {
	opts := &ocsp.RequestOptions{Hash: crypto.SHA1}

	buffer, err := ocsp.CreateRequest(certificate, issuer, opts)
	if err != nil {
		return nil, fmt.Errorf("could not generate OCSP request: %s", err)
	}

	var httpRequest *http.Request

	switch method {
	case http.MethodPost:
		httpRequest, err = http.NewRequest(http.MethodPost, ocspServerURL, bytes.NewBuffer(buffer))
	case http.MethodGet:
		encOCSPReq := base64.URLEncoding.EncodeToString(buffer)
		httpRequest, err = http.NewRequest(http.MethodGet, fmt.Sprintf("%s/%s", ocspServerURL, encOCSPReq), nil)
	default:
		return nil, fmt.Errorf("unsupported HTTP OCSP request method: %s", method)
	}

	if err != nil {
		return nil, fmt.Errorf("could not generate HTTP OCSP request: %s", err)
	}

	ocspUrl, err := url.Parse(ocspServerURL)
	if err != nil {
		return nil, fmt.Errorf("could not parse OCSP server URL: %s", err)
	}

	httpRequest.Header.Add("Content-Type", "application/ocsp-request")
	httpRequest.Header.Add("Accept", "application/ocsp-response")
	httpRequest.Header.Add("Host", ocspUrl.Host)

	httpClient := &http.Client{Timeout: revocationRequestTimeout}
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
		return nil, fmt.Errorf("could not execute OCSP request: %w; Request method: %s, URL: %s",
			err, httpRequest.Method, httpRequest.URL)
	}
	defer httpResponse.Body.Close()

	// Check for a non-2xx status code (failure in request)
	if httpResponse.StatusCode < 200 || httpResponse.StatusCode >= 300 {
		return nil, fmt.Errorf("OCSP request failed with status code %d: %s; Request method: %s, URL: %s",
			httpResponse.StatusCode, httpResponse.Status, httpRequest.Method, httpRequest.URL)
	}

	output, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		return nil, fmt.Errorf("could not decode OCSP response: %s", err)
	}

	ocspIssuer := issuer
	if !verifyOCSPResponse {
		ocspIssuer = nil
	}

	response, err := ocsp.ParseResponse(output, ocspIssuer)
	if err != nil {
		return nil, fmt.Errorf("could not parse OCSP response: %w", err)
	}

	if verifyOCSPResponse {
		if err := checkDelegatedResponder(response, issuer); err != nil {
			return nil, err
		}
	}

	return response, nil
}

// checkDelegatedResponder enforces RFC 6960 4.2.2.2: a response signed by a certificate other than the issuer must
// come from a delegated responder carrying the id-kp-OCSPSigning EKU and within its validity period.
// ocsp.ParseResponse only checks that the responder certificate was signed by the issuer, which any end-entity
// certificate of that CA satisfies, expired ones included.
func checkDelegatedResponder(response *ocsp.Response, issuer *x509.Certificate) error {
	responder := response.Certificate
	if responder == nil || responder.Equal(issuer) {
		return nil
	}

	if !slices.Contains(responder.ExtKeyUsage, x509.ExtKeyUsageOCSPSigning) {
		return fmt.Errorf("OCSP response signed by %q, which is not the issuer and is not authorized for OCSP signing", responder.Subject.CommonName)
	}

	now := time.Now()
	if now.Before(responder.NotBefore) || now.After(responder.NotAfter) {
		return fmt.Errorf("OCSP response signed by %q, whose certificate is not valid at this time (valid from %s to %s)",
			responder.Subject.CommonName, responder.NotBefore.UTC().Format(time.RFC3339), responder.NotAfter.UTC().Format(time.RFC3339))
	}

	return nil
}
