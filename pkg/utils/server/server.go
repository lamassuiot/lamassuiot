package server

import (
	"crypto/tls"
	"net/http"
	"os"
	"strings"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/lamassuiot/lamassuiot/pkg/utils"
)

type ServerConfiguration struct {
	Port string

	Protocol string

	CertFile string
	KeyFile  string

	MutualTLSEnabled  bool
	MutualTLSClientCA string
}

func (cfg *ServerConfiguration) RunServer(logger log.Logger, errs chan error) {
	if strings.ToLower(cfg.Protocol) == "https" {
		if cfg.MutualTLSEnabled {
			mTlsCertPool, err := utils.CreateCAPool(cfg.MutualTLSClientCA)
			if err != nil {
				level.Error(logger).Log("err", err, "msg", "Could not create mTls Cert Pool")
				os.Exit(1)
			}

			tlsConfig := &tls.Config{
				ClientCAs:  mTlsCertPool,
				ClientAuth: tls.RequireAndVerifyClientCert,
			}

			http := &http.Server{
				Addr:      ":" + cfg.Port,
				TLSConfig: tlsConfig,
			}

			level.Info(logger).Log("transport", "Mutual TLS", "address", ":"+cfg.Port, "msg", "listening")
			errs <- http.ListenAndServeTLS(cfg.CertFile, cfg.KeyFile)

		} else {
			level.Info(logger).Log("transport", "HTTPS", "address", ":"+cfg.Port, "msg", "listening")
			errs <- http.ListenAndServeTLS(":"+cfg.Port, cfg.CertFile, cfg.KeyFile, nil)
		}

	} else if strings.ToLower(cfg.Protocol) == "http" {
		level.Info(logger).Log("transport", "HTTP", "address", ":"+cfg.Port, "msg", "listening")
		errs <- http.ListenAndServe(":"+cfg.Port, nil)

	} else {
		level.Error(logger).Log("err", "msg", "Unknown protocol")
		os.Exit(1)
	}
}
