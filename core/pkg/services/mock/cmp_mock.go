package mock

import (
	"context"
	"crypto"
	"crypto/x509"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/stretchr/testify/mock"
)

// MockLightweightCMPService is a testify mock that satisfies
// LightweightCMPService plus the optional LightweightCMPProtectionProvider.
type MockLightweightCMPService struct {
	mock.Mock
}

func (m *MockLightweightCMPService) LWCEnroll(ctx context.Context, csr *x509.CertificateRequest, aps string) (*x509.Certificate, error) {
	args := m.Called(ctx, csr, aps)
	cert, _ := args.Get(0).(*x509.Certificate)
	return cert, args.Error(1)
}

func (m *MockLightweightCMPService) LWCReenroll(ctx context.Context, csr *x509.CertificateRequest, aps string) (*x509.Certificate, error) {
	args := m.Called(ctx, csr, aps)
	cert, _ := args.Get(0).(*x509.Certificate)
	return cert, args.Error(1)
}

func (m *MockLightweightCMPService) LWCCACerts(ctx context.Context, aps string) ([]*x509.Certificate, error) {
	args := m.Called(ctx, aps)
	certs, _ := args.Get(0).([]*x509.Certificate)
	return certs, args.Error(1)
}

func (m *MockLightweightCMPService) LWCRevokeCertificate(ctx context.Context, input services.RevokeCertificateInput) error {
	args := m.Called(ctx, input)
	return args.Error(0)
}

func (m *MockLightweightCMPService) LWCGetRootCACertUpdate(ctx context.Context, input services.GetRootCACertUpdateInput) (*services.RootCACertUpdateOutput, error) {
	args := m.Called(ctx, input)
	out, _ := args.Get(0).(*services.RootCACertUpdateOutput)
	return out, args.Error(1)
}

func (m *MockLightweightCMPService) LWCGetCertReqTemplate(ctx context.Context, input services.GetCertReqTemplateInput) (*services.CertReqTemplateOutput, error) {
	args := m.Called(ctx, input)
	out, _ := args.Get(0).(*services.CertReqTemplateOutput)
	return out, args.Error(1)
}

func (m *MockLightweightCMPService) LWCGetCRL(ctx context.Context, input services.GetCMPCRLInput) (*x509.RevocationList, error) {
	args := m.Called(ctx, input)
	crl, _ := args.Get(0).(*x509.RevocationList)
	return crl, args.Error(1)
}

func (m *MockLightweightCMPService) LWCGetEnrollmentOptions(ctx context.Context, aps string) (*services.LWCEnrollmentOptions, error) {
	args := m.Called(ctx, aps)
	opts, _ := args.Get(0).(*services.LWCEnrollmentOptions)
	return opts, args.Error(1)
}

// MockLightweightCMPServiceWithProtection extends MockLightweightCMPService
// with the optional LightweightCMPProtectionProvider interface.
// Use this in tests that exercise protected-response paths.
type MockLightweightCMPServiceWithProtection struct {
	MockLightweightCMPService
}

func (m *MockLightweightCMPServiceWithProtection) LWCProtectionCredentials(aps string) ([]*x509.Certificate, crypto.Signer, error) {
	args := m.Called(aps)
	certs, _ := args.Get(0).([]*x509.Certificate)
	signer, _ := args.Get(1).(crypto.Signer)
	return certs, signer, args.Error(2)
}
