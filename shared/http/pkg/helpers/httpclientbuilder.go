package helpers

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/shared/http/v3/pkg/utils/gindump"
	"github.com/sirupsen/logrus"
)

func BuildHTTPClientWithTLSOptions(cli *http.Client, cfg config.TLSConfig) (*http.Client, error) {
	caPool := chelpers.LoadSytemCACertPool()
	tlsConfig := &tls.Config{}

	if cfg.InsecureSkipVerify {
		tlsConfig.InsecureSkipVerify = true
	}

	if cfg.CACertificateFile != "" {
		cert, err := chelpers.ReadCertificateFromFile(cfg.CACertificateFile)
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

func BuildHTTPClientWithTracerLogger(cli *http.Client, logger *logrus.Entry) (*http.Client, error) {
	transport := http.DefaultTransport
	if cli.Transport != nil {
		transport = cli.Transport
	}

	cli.Transport = loggingRoundTripper{
		transport: transport,
		logger:    logger,
	}

	return cli, nil
}

type loggingRoundTripper struct {
	transport http.RoundTripper
	logger    *logrus.Entry
}

func (lrt loggingRoundTripper) RoundTrip(req *http.Request) (res *http.Response, err error) {
	start := time.Now()
	dReq := gindump.DumpRequest(req, true, true)
	res, err = lrt.transport.RoundTrip(req)
	lFunc := chelpers.ConfigureLogger(req.Context(), lrt.logger)
	if err != nil {
		lFunc.Errorf("%s: %s", req.URL.String(), err)
	} else {
		log := lFunc.WithField("response", fmt.Sprintf("%s %d: %s", req.Method, res.StatusCode, time.Since(start)))
		log.Debug(req.URL.String())
		log.Tracef("%s\n%s", dReq, gindump.DumpResponse(res, true, true))
	}

	return
}
