package sdk

import (
	"context"
	"errors"
	"fmt"
	"log"
	"runtime"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

func InitOtelSDK(ctx context.Context, svcName string) (func(context.Context) error, error) {
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

	err = setupTracerProvider(ctx, resources)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}

	err = setupMeterProvider(ctx, resources)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}

	// Set up the text map propagator to inject trace headers into HTTP requests
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return shutdown, err
}

func setupTracerProvider(ctx context.Context, resources *resource.Resource) error {
	exporter, err := otlptrace.New(
		ctx,
		otlptracehttp.NewClient(
			// NOTE: it might be better to configure it as an Environment Variable
			otlptracehttp.WithEndpoint("localhost:4318"),
			otlptracehttp.WithInsecure(),
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

func setupMeterProvider(ctx context.Context, resources *resource.Resource) error {
	exporter, err := otlpmetrichttp.New(
		ctx,
		otlpmetrichttp.WithEndpoint("localhost:4318"),
		otlpmetrichttp.WithInsecure(),
	)

	if err != nil {
		return err
	}

	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exporter)))

	otel.SetMeterProvider(mp)

	return nil
}

func GetCallerFunctionName() string {
	pc, _, _, _ := runtime.Caller(1)

	fullName := fmt.Sprintf("%s", runtime.FuncForPC(pc).Name())
	split := strings.Split(fullName, ".")

	return split[len(split)-1]
}

type Metrics struct {
	MemoryUsage metric.Int64Gauge
}

func NewMetrics(serviceName string) (*Metrics, error) {
	var m Metrics
	var err error
	meter := otel.GetMeterProvider().Meter(serviceName)

	// Record memory usage
	m.MemoryUsage, err = meter.Int64Gauge(
		"system_memory_usage",
		metric.WithDescription("RAM usage"),
		metric.WithUnit("bytes"),
	)
	if err != nil {
		return nil, err
	}
		

	return &m, nil
}

func GetMemoryUsage() uint64 {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	currentMemoryUsage := memStats.HeapAlloc
	return currentMemoryUsage
}
