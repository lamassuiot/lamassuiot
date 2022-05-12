// Copyright 2016 SMFS Inc DBA GRIMM. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.
package main

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	kitprometheus "github.com/go-kit/kit/metrics/prometheus"
	lamassucaclient "github.com/lamassuiot/lamassuiot/pkg/ca/client"
	"github.com/lamassuiot/lamassuiot/pkg/ocsp/server/api/service"
	"github.com/lamassuiot/lamassuiot/pkg/ocsp/server/api/transport"
	configs "github.com/lamassuiot/lamassuiot/pkg/ocsp/server/configs"
	"github.com/lamassuiot/lamassuiot/pkg/ocsp/server/secrets/responder/file"
	clientUtils "github.com/lamassuiot/lamassuiot/pkg/utils/client"
	stdprometheus "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	jaegercfg "github.com/uber/jaeger-client-go/config"

	_ "github.com/lib/pq"
)

func main() {
	var logger log.Logger
	{
		logger = log.NewJSONLogger(os.Stdout)
		logger = log.With(logger, "ts", log.DefaultTimestampUTC)
		logger = log.With(logger, "caller", log.DefaultCaller)
		logger = level.NewFilter(logger, level.AllowInfo())
	}
	cfg, err := configs.NewConfig("")

	lamassuCaClient, err := lamassucaclient.NewLamassuCAClient(clientUtils.ClientConfiguration{
		URL: &url.URL{
			Scheme: "https",
			Host:   cfg.LamassuCAAddress,
		},
		AuthMethod: clientUtils.MutualTLS,
		AuthMethodConfig: &clientUtils.MutualTLSConfig{
			ClientCert: cfg.CertFile,
			ClientKey:  cfg.KeyFile,
		},
		CACertificate: cfg.LamassuCACertFile,
	})
	if err != nil {
		level.Error(logger).Log("err", err)
		os.Exit(1)
	}

	respSecrets := file.NewFile(*&cfg.Key, *&cfg.Cert, logger)

	jcfg, err := jaegercfg.FromEnv()
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not load Jaeger configuration values fron environment")
		os.Exit(1)
	}

	level.Info(logger).Log("msg", "Jaeger configuration values loaded")
	tracer, closer, err := jcfg.NewTracer()
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not start Jaeger tracer")
		os.Exit(1)
	}
	defer closer.Close()
	level.Info(logger).Log("msg", "Jaeger tracer started")
	fieldKeys := []string{"method", "error"}

	var resp service.Service
	{
		resp, err = service.NewService(respSecrets, &lamassuCaClient)
		if err != nil {
			logger.Log("err", err)
			os.Exit(1)
		}
		resp = service.LoggingMiddleware(logger)(resp)
		resp = service.NewInstrumentingMiddleware(
			kitprometheus.NewCounterFrom(stdprometheus.CounterOpts{
				Namespace: "ocsp_responder",
				Subsystem: "responder",
				Name:      "request_count",
				Help:      "Number of requests received.",
			}, fieldKeys),
			kitprometheus.NewSummaryFrom(stdprometheus.SummaryOpts{
				Namespace: "ocsp_responder",
				Subsystem: "responder",
				Name:      "request_latency_microseconds",
				Help:      "Total duration of requests in microseconds.",
			}, fieldKeys),
		)(resp)
	}

	h := transport.MakeHTTPHandler(resp, log.With(logger, "component", "HTTP"), *&cfg.Strict, tracer)
	http.Handle("/metrics", promhttp.Handler())

	errs := make(chan error)
	go func() {
		c := make(chan os.Signal)
		signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
		errs <- fmt.Errorf("%s", <-c)
	}()

	if *&cfg.SSL {
		go func() {
			level.Info(logger).Log("transport", "HTTPS", "address", *&cfg.Address+":"+*&cfg.Port, "msg", "listening")
			errs <- http.ListenAndServeTLS(*&cfg.Address+":"+*&cfg.Port, *&cfg.Cert, *&cfg.Key, nil)
		}()
	} else {
		go func() {
			level.Info(logger).Log("transport", "HTTP", "address", *&cfg.Address+":"+*&cfg.Port, "msg", "listening")
			errs <- http.ListenAndServe(*&cfg.Address+":"+*&cfg.Port, h)
		}()
	}
	level.Info(logger).Log("exit", <-errs)
}
