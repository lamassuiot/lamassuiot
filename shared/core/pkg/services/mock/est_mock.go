package mock

import (
	"context"
	"crypto/x509"

	"github.com/stretchr/testify/mock"
)

type MockESTService struct {
	mock.Mock
}

func (m *MockESTService) Enroll(ctx context.Context, csr *x509.CertificateRequest, aps string) (*x509.Certificate, error) {
	args := m.Called(ctx, csr, aps)
	return args.Get(0).(*x509.Certificate), args.Error(1)
}

func (m *MockESTService) Reenroll(ctx context.Context, csr *x509.CertificateRequest, aps string) (*x509.Certificate, error) {
	args := m.Called(ctx, csr, aps)
	return args.Get(0).(*x509.Certificate), args.Error(1)
}

func (m *MockESTService) CACerts(ctx context.Context, aps string) ([]*x509.Certificate, error) {
	args := m.Called(ctx, aps)
	return args.Get(0).([]*x509.Certificate), args.Error(1)
}

func (m *MockESTService) ServerKeyGen(ctx context.Context, csr *x509.CertificateRequest, aps string) (*x509.Certificate, interface{}, error) {
	args := m.Called(ctx, csr, aps)
	return args.Get(0).(*x509.Certificate), args.Get(1), args.Error(2)
}
