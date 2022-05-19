package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-kit/log"

	"github.com/lamassuiot/lamassuiot/pkg/utils"
	"go.mozilla.org/pkcs7"
)

type LamassuEstClientConfig struct {
	Client                 BaseClient
	EstServerAddress       string
	EstServerCaCertificate *x509.CertPool
	EstClientCertificate   *x509.Certificate
	EstClientKey           interface{}
	logger                 log.Logger
}

type LamassuEstClient interface {
	CACerts(ctx context.Context) ([]*x509.Certificate, error)
	Enroll(ctx context.Context, aps string, csr *x509.CertificateRequest) (*x509.Certificate, error)
	Reenroll(ctx context.Context, csr *x509.CertificateRequest /*, crt *x509.Certificate*/) (*x509.Certificate, error)
	ServerKeyGen(ctx context.Context, aps string, csr *x509.CertificateRequest) (*x509.Certificate, []byte, error)
}

func NewLamassuEstClient(estServerAddress string, serverCertPool *x509.CertPool, clientCert *x509.Certificate, clientKey []byte, logger log.Logger) (LamassuEstClient, error) {
	b := pem.Block{Type: "CERTIFICATE", Bytes: clientCert.Raw}
	certPEM := pem.EncodeToMemory(&b)
	cert, err := tls.X509KeyPair(certPEM, clientKey)
	if err != nil {
		return nil, err
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:            serverCertPool,
				Certificates:       []tls.Certificate{cert},
				InsecureSkipVerify: true,
			},
		},
	}

	u, err := url.Parse(estServerAddress)
	if err != nil {
		return nil, err
	}

	return &LamassuEstClientConfig{
		Client:                 NewBaseClient(u, httpClient),
		EstServerAddress:       estServerAddress,
		EstServerCaCertificate: serverCertPool,
		EstClientCertificate:   clientCert,
		EstClientKey:           clientKey,
		logger:                 logger,
	}, nil
}

func (c *LamassuEstClientConfig) CACerts(ctx context.Context) ([]*x509.Certificate, error) {
	var resp *http.Response
	var body []byte
	if ctx != nil {
		req, err := c.Client.NewRequest(http.MethodGet, "/cacerts", c.EstServerAddress, "", "", "", "application/pkcs7-mime", nil)
		if err != nil {
			return nil, err
		}

		resp, body, err = c.Client.Do(req)
		if err != nil {
			return nil, err
		}
	} else {
		req, err := c.Client.NewRequest(http.MethodGet, "/cacerts", c.EstServerAddress, "", "", "", "application/pkcs7-mime", nil)
		if err != nil {
			return nil, err
		}

		resp, body, err = c.Client.Do(req)
		if err != nil {
			return nil, err
		}
	}

	if err := checkResponseError(resp); err != nil {
		return nil, err
	}

	if err := verifyResponseType(resp, "application/pkcs7-mime", "base64"); err != nil {
		return nil, err
	}

	decoded, err := utils.DecodeB64(string(body))
	if err != nil {
		return nil, errInvalidBase64
	}

	p7, err := pkcs7.Parse([]byte(decoded))
	if err != nil {
		return nil, errInvalidPKCS7
	}
	return p7.Certificates, nil
}

func (c *LamassuEstClientConfig) Enroll(ctx context.Context, aps string, csr *x509.CertificateRequest) (*x509.Certificate, error) {
	reqBody := ioutil.NopCloser(bytes.NewBuffer(utils.EncodeB64(csr.Raw)))
	var resp *http.Response
	var body []byte

	req, err := c.Client.NewRequest(http.MethodPost, "/simpleenroll", c.EstServerAddress, aps, "application/pkcs10", "base64", "application/pkcs7-mime", reqBody)
	if err != nil {
		return nil, err
	}

	resp, body, err = c.Client.Do(req)
	if err != nil {
		return nil, err
	}

	if err := checkResponseError(resp); err != nil {
		return nil, err
	}

	if err := verifyResponseType(resp, "application/pkcs7-mime", "base64"); err != nil {
		return nil, err
	}

	decoded, err := utils.DecodeB64(string(body))
	if err != nil {
		return nil, errInvalidBase64
	}

	certs, err := DecodePKCS7CertsOnly([]byte(decoded))
	if err != nil {
		return nil, errInvalidPKCS7
	}

	return certs[0], nil
}

func (c *LamassuEstClientConfig) Reenroll(ctx context.Context, csr *x509.CertificateRequest /*, crt *x509.Certificate*/) (*x509.Certificate, error) {
	reqBody := ioutil.NopCloser(bytes.NewBuffer(utils.EncodeB64(csr.Raw)))
	var resp *http.Response
	var body []byte

	req, err := c.Client.NewRequest(http.MethodPost, "/simplereenroll", c.EstServerAddress, "", "application/pkcs10", "base64", "application/pkcs7-mime", reqBody)
	if err != nil {
		return nil, err
	}

	resp, body, err = c.Client.Do(req)
	if err != nil {
		return nil, err
	}

	if err := checkResponseError(resp); err != nil {
		return nil, err
	}

	if err := verifyResponseType(resp, "application/pkcs7-mime", "base64"); err != nil {
		return nil, err
	}

	decoded, err := utils.DecodeB64(string(body))
	if err != nil {
		return nil, errInvalidBase64
	}

	certs, err := DecodePKCS7CertsOnly([]byte(decoded))
	if err != nil {
		return nil, errInvalidPKCS7
	}

	return certs[0], nil
}

func (c *LamassuEstClientConfig) ServerKeyGen(ctx context.Context, aps string, csr *x509.CertificateRequest) (*x509.Certificate, []byte, error) {
	reqBody := ioutil.NopCloser(bytes.NewBuffer(utils.EncodeB64(csr.Raw)))
	var resp *http.Response
	req, err := c.Client.NewRequest(http.MethodPost, "/serverkeygen", c.EstServerAddress, aps, "application/pkcs10", "base64", "multipart/mixed", reqBody)
	if err != nil {
		return nil, nil, err
	}
	resp, body, err := c.Client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer consumeAndClose(resp.Body)
	resp.Body = ioutil.NopCloser(bytes.NewBuffer(body))
	if err := checkResponseError(resp); err != nil {
		return nil, nil, err
	}

	mediaType, params, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		return nil, nil, err
	} else if !strings.HasPrefix(mediaType, "multipart/mixed") {
		return nil, nil, err
	}

	mpr := multipart.NewReader(resp.Body, params["boundary"])

	cert, key, err := ProcessAllParts(mpr)
	if err != nil {
		return nil, nil, err
	}
	return cert[0], key, nil

}

func checkResponseError(r *http.Response) error {
	if r.StatusCode == http.StatusOK {
		return nil
	}
	var msg string
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err == nil || r.Header.Get("Content-Type") == "" {
		switch mediaType {
		case "", "text/plain", "application/json", "application/problem+json":
			data, err := ioutil.ReadAll(r.Body)
			if err != nil {
				return err
			}

			if len(data) > 0 {
				msg = string(data)
			} else {
				msg = http.StatusText(r.StatusCode)
			}

		default:
			msg = fmt.Sprintf("%s (%s)",
				http.StatusText(r.StatusCode), mediaType)
		}
	}
	var retryAfter int
	if secs := r.Header.Get("Retry-After"); secs != "" {
		retryAfter, err = strconv.Atoi(secs)
		if err != nil {
			if t, err := http.ParseTime(secs); err == nil {
				retryAfter = int(t.Sub(time.Now()).Seconds())
			}
		}

		if retryAfter < 0 {
			retryAfter = 0
		}
	}

	return &estError{
		status:     r.StatusCode,
		desc:       msg,
		retryAfter: retryAfter,
	}
}

func verifyResponseType(r *http.Response, t, e string) error {
	ctype, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		return err
	}

	if !strings.HasPrefix(ctype, t) {
		return errors.New("unexpected Content-Type:" + ctype)
	}

	cenc := r.Header.Get("Content-Transfer-Encoding")
	if cenc == "" {
		return errors.New("missing Content-Transfer-Encoding header")
	}

	if strings.ToUpper(cenc) != strings.ToUpper(e) {
		return errors.New("unexpected Content-Transfer-Encoding: " + cenc)
	}

	return nil
}
func ProcessAllParts(mpr *multipart.Reader) ([]*x509.Certificate, []byte, error) {
	var cert []*x509.Certificate
	var key []byte
	var numParts = 2
	for i := 1; ; i++ {
		part, err := mpr.NextPart()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, nil, err
		}
		defer part.Close()
		if i > numParts {
			return nil, nil, errors.New("more than" + string(numParts) + "parts in HTTP response")
		}

		if ce := part.Header.Get("Content-Transfer-Encoding"); ce == "" {
			return nil, nil, errors.New("missing Content-Transfer-Encoding header")
		} else if strings.ToUpper(ce) != strings.ToUpper("base64") {
			return nil, nil, errors.New("unexpected Content-Transfer-Encoding: " + ce)
		}

		mediaType, params, err := mime.ParseMediaType(part.Header.Get("Content-Type"))
		if err != nil {
			return nil, nil, err
		}

		switch {
		case strings.HasPrefix(mediaType, "application/pkcs8"):
			key, err = ReadAllBase64Response(part)
			if err != nil {
				return nil, nil, err
			}

		case strings.HasPrefix(mediaType, "application/pkcs7-mime"):
			t := params["smime-type"]

			switch t {
			case "server-generated-key":
				key, err = ReadAllBase64Response(part)
				if err != nil {
					return nil, nil, err
				}

			case "certs-only":
				cert, err = ReadCertResponse(part)
				if err != nil {
					return nil, nil, err
				}

			default:
				return nil, nil, err

			}

		default:
			return nil, nil, errors.New("unexpected Content Type:" + mediaType)
		}

	}

	if cert == nil {
		return nil, nil, errors.New("no certificate returned")
	} else if key == nil {
		return nil, nil, errors.New("no private key returned")
	}

	return cert, key, nil
}

func consumeAndClose(rc io.ReadCloser) {
	io.Copy(ioutil.Discard, rc)
	rc.Close()
}
