package services

import (
	"context"
	"errors"
	"testing"

	core "github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
)

func TestCAQueriesRequireTenantContext(t *testing.T) {
	service := &CAServiceBackend{
		logger: logrus.New().WithField("test", "ca-tenant"),
	}
	ctx := context.Background()

	tests := []struct {
		name string
		call func() error
	}{
		{
			name: "get stats",
			call: func() error {
				_, err := service.GetStats(ctx, services.GetStatsInput{})
				return err
			},
		},
		{
			name: "get certificate by serial",
			call: func() error {
				_, err := service.GetCertificateBySerialNumber(ctx, services.GetCertificatesBySerialNumberInput{SerialNumber: "serial"})
				return err
			},
		},
		{
			name: "list certificates",
			call: func() error {
				_, err := service.GetCertificates(ctx, services.GetCertificatesInput{})
				return err
			},
		},
		{
			name: "list certificates by CA",
			call: func() error {
				_, err := service.GetCertificatesByCA(ctx, services.GetCertificatesByCAInput{CAID: "ca"})
				return err
			},
		},
		{
			name: "list certificates by status",
			call: func() error {
				_, err := service.GetCertificatesByStatus(ctx, services.GetCertificatesByStatusInput{})
				return err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.call(); !errors.Is(err, core.ErrTenantContextRequired) {
				t.Fatalf("expected ErrTenantContextRequired, got %v", err)
			}
		})
	}
}

func TestCAOperationsRequireTenantContextBeforeDependencies(t *testing.T) {
	service := &CAServiceBackend{
		logger: logrus.New().WithField("test", "ca-tenant"),
	}
	ctx := context.Background()
	if _, err := service.CreateCA(ctx, services.CreateCAInput{}); !errors.Is(err, core.ErrTenantContextRequired) {
		t.Fatalf("expected CA creation to require tenant context, got %v", err)
	}
	if _, err := service.SignCertificate(ctx, services.SignCertificateInput{}); !errors.Is(err, core.ErrTenantContextRequired) {
		t.Fatalf("expected certificate signing to require tenant context, got %v", err)
	}
	if _, err := service.CreateIssuanceProfile(ctx, services.CreateIssuanceProfileInput{}); !errors.Is(err, core.ErrTenantContextRequired) {
		t.Fatalf("expected profile creation to require tenant context, got %v", err)
	}
}
