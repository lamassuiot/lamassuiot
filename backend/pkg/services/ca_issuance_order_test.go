package services

import (
	"context"
	"errors"
	"testing"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
)

type insertOnlyCertStorage struct {
	storage.CertificatesRepo
	err      error
	inserted int
}

func (repo *insertOnlyCertStorage) Insert(_ context.Context, cert *models.Certificate) (*models.Certificate, error) {
	if repo.err != nil {
		return nil, repo.err
	}
	repo.inserted++
	return cert, nil
}

func TestIssuedCertificateIsStoredBeforeItsKeyIsBound(t *testing.T) {
	failing := &insertOnlyCertStorage{err: errors.New("database unavailable")}
	bound := 0
	svc := &CAServiceBackend{certStorage: failing}
	if _, err := svc.storeIssuedCertificate(context.Background(), &models.Certificate{SerialNumber: "01"}, func() { bound++ }); err == nil {
		t.Fatal("expected the insert error to be returned")
	}
	if bound != 0 {
		t.Fatal("the KMS key must not be bound when the certificate could not be stored")
	}

	working := &insertOnlyCertStorage{}
	svc = &CAServiceBackend{certStorage: working}
	stored, err := svc.storeIssuedCertificate(context.Background(), &models.Certificate{SerialNumber: "02"}, func() { bound++ })
	if err != nil || stored == nil || working.inserted != 1 || bound != 1 {
		t.Fatalf("expected stored and bound certificate, got stored=%v err=%v inserted=%d bound=%d", stored, err, working.inserted, bound)
	}

	caCert := &models.Certificate{SerialNumber: "03", IsCA: true}
	stored, err = svc.storeIssuedCertificate(context.Background(), caCert, func() { bound++ })
	if err != nil || stored != caCert || working.inserted != 1 || bound != 2 {
		t.Fatalf("CA certificates are stored by CreateCA, not here; got inserted=%d bound=%d err=%v", working.inserted, bound, err)
	}
}
