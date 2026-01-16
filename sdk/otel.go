package sdk

import (
	"context"
	"errors"
	"fmt"
	"log"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"go.opentelemetry.io/contrib/instrumentation/host"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

var (
	otelInitOnce     sync.Once
	otelShutdownFunc func(context.Context) error
	otelInitErr      error
)

func InitOtelSDK(ctx context.Context, svcName string, config config.OTELConfig) (func(context.Context) error, error) {
	otelInitOnce.Do(func() {
		otelShutdownFunc, otelInitErr = initOtelSDKInternal(ctx, svcName, config)
	})
	return otelShutdownFunc, otelInitErr
}

func initOtelSDKInternal(ctx context.Context, svcName string, config config.OTELConfig) (func(context.Context) error, error) {
	var shutdownFuncs []func(context.Context) error
	var err error

	shutdown := func(ctx context.Context) error {
		var err error

		for _, fn := range shutdownFuncs {
			err = errors.Join(err, fn(ctx))
		}

		shutdownFuncs = nil

		return err
	}

	handleErr := func(inErr error) {
		err = errors.Join(inErr, shutdown(ctx))
	}

	resources, err := resource.New(
		context.Background(),
		resource.WithAttributes(
			attribute.String("service.name", svcName),
			attribute.String("library.language", "go"),
		),
	)
	if err != nil {
		handleErr(err)
		log.Printf("Could not set resources: %s", err)
		return shutdown, err
	}

	if config.Traces.Enabled {
		err = setupTracerProvider(ctx, config.Traces, resources)
		if err != nil {
			log.Fatal(err)
			return nil, err
		}
	}

	if config.Metrics.Enabled {
		err = setupMeterProvider(ctx, config.Metrics, resources)
		if err != nil {
			log.Fatal(err)
			return nil, err
		}
	}

	// Set up the text map propagator to inject trace headers into HTTP requests
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return shutdown, err
}

func setupTracerProvider(ctx context.Context, config config.OTELTracesConfig, resources *resource.Resource) error {
	options := []otlptracehttp.Option{
		otlptracehttp.WithEndpoint(fmt.Sprintf("%s:%d", config.Hostname, config.Port)),
	}

	if config.Scheme == "http" {
		options = append(options, otlptracehttp.WithInsecure())
	}

	exporter, err := otlptrace.New(
		ctx,
		otlptracehttp.NewClient(
			options...,
		),
	)
	if err != nil {
		return err
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(resources),
	)

	// Register the global tracer provider
	otel.SetTracerProvider(tp)

	return nil
}

func setupMeterProvider(ctx context.Context, config config.OTELMetricsConfig, resources *resource.Resource) error {
	options := []otlpmetrichttp.Option{
		otlpmetrichttp.WithEndpoint(fmt.Sprintf("%s:%d", config.Hostname, config.Port)),
	}

	if config.Scheme == "http" {
		options = append(options, otlpmetrichttp.WithInsecure())
	}

	exporter, err := otlpmetrichttp.New(
		ctx,
		options...,
	)

	if err != nil {
		return err
	}

	interval, _ := time.ParseDuration(fmt.Sprintf("%dms", config.IntervalInMillis))

	// Register the exporter with an SDK via a periodic reader.
	mp := metric.NewMeterProvider(metric.WithReader(metric.NewPeriodicReader(exporter, metric.WithInterval(interval))), metric.WithResource(resources))

	err = host.Start(host.WithMeterProvider(mp))
	if err != nil {
		log.Fatal(err)
	}

	otel.SetMeterProvider(mp)

	return nil
}

func GetCallerFunctionName() string {
	pc, _, _, _ := runtime.Caller(1)

	fullName := fmt.Sprintf("%s", runtime.FuncForPC(pc).Name())
	split := strings.Split(fullName, ".")

	return split[len(split)-1]
}
