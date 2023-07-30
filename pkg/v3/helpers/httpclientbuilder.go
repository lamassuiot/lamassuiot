package helpers

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/lamassuiot/lamassuiot/pkg/v3/config"
	"github.com/sirupsen/logrus"
)

func BuildHTTPClientWithTLSOptions(cli *http.Client, cfg config.TLSConfig) (*http.Client, error) {
	caPool := LoadSytemCACertPool()
	tlsConfig := &tls.Config{}

	if cfg.InsecureSkipVerify {
		tlsConfig.InsecureSkipVerify = true
	}

	if cfg.CACertificateFile != "" {
		cert, err := ReadCertificateFromFile(cfg.CACertificateFile)
		if err != nil {
			return nil, err
		}

		caPool.AddCert(cert)
	}

	cli.Transport = &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	return cli, nil
}

func BuildHTTPClientWithloggger(cli *http.Client, logger *logrus.Entry) (*http.Client, error) {
	transport := http.DefaultTransport
	if cli.Transport != nil {
		transport = cli.Transport
	}

	cli.Transport = loggingRoundTripper{
		proxied: transport,
		logger:  logger,
	}

	return cli, nil
}

type loggingRoundTripper struct {
	proxied http.RoundTripper
	logger  *logrus.Entry
}

func (lrt loggingRoundTripper) RoundTrip(req *http.Request) (res *http.Response, err error) {
	start := time.Now()
	// Send the request, get the response (or the error)
	res, err = lrt.proxied.RoundTrip(req)

	// Handle the result.
	log := lrt.logger.WithField("response", fmt.Sprintf("%s %d: %s", req.Method, res.StatusCode, time.Since(start)))

	if err != nil {
		log = log.WithField("error", err.Error())
		log.Errorf(req.URL.String())
	} else {
		log.Tracef(req.URL.String())
	}

	return
}
