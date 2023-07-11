package helpers

import (
	"crypto/tls"
	"net/http"
	"time"

	"github.com/lamassuiot/lamassuiot/pkg/v3/config"
	log "github.com/sirupsen/logrus"
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

func BuildHTTPClientWithloggger(cli *http.Client, clientName string) (*http.Client, error) {
	cli.Transport = loggingRoundTripper{
		Proxied:    cli.Transport,
		ClientName: clientName,
	}

	return cli, nil
}

type loggingRoundTripper struct {
	Proxied    http.RoundTripper
	ClientName string
}

func (lrt loggingRoundTripper) RoundTrip(req *http.Request) (res *http.Response, err error) {
	start := time.Now()
	// Send the request, get the response (or the error)
	res, err = lrt.Proxied.RoundTrip(req)

	httpLogger := *log.StandardLogger()
	// Handle the result.
	if err != nil {
		httpLogger.Tracef("[%s] %s %s - error:%q - %v", lrt.ClientName, req.Method, req.URL.String(), err.Error(), time.Since(start))
	} else {
		httpLogger.Tracef("[%s] %s %s - %s - %v", lrt.ClientName, req.Method, req.URL.String(), res.Status, time.Since(start))
	}

	return
}

type customLogger struct {
	defaultField string
	formatter    log.Formatter
}

func (l customLogger) Format(entry *log.Entry) ([]byte, error) {
	entry.Data["field_name"] = l.defaultField
	return l.formatter.Format(entry)
}
