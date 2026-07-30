package eventpub

import (
	"context"
	"crypto/x509"
	"testing"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	svcmock "github.com/lamassuiot/lamassuiot/core/v3/pkg/services/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// kgaRecipientValidatingMock extends the base DMS manager mock with
// LWCValidateKGARecipient, so it satisfies services.LightweightCMPKGARecipientValidator
// in addition to services.DMSManagerService.
type kgaRecipientValidatingMock struct {
	*svcmock.MockDMSManagerService
	called bool
}

func (m *kgaRecipientValidatingMock) LWCValidateKGARecipient(ctx context.Context, aps string, recipient *x509.Certificate) error {
	m.called = true
	return nil
}

// TestDMSEventPublisher_ForwardsLWCValidateKGARecipient is a regression test
// for a real production bug: a new optional CMP capability interface
// (services.LightweightCMPKGARecipientValidator, added alongside the
// CKG-recipient-trust fix) was added to the underlying DMSManagerServiceBackend
// but NOT forwarded by this middleware — since dmsEventPublisher implements
// every method of services.DMSManagerService explicitly (no embedding), a type
// assertion for an optional interface on the wrapped value only succeeds if
// dmsEventPublisher itself also implements that interface, regardless of
// whether the wrapped `next` service does. Central Key Generation (RFC 9483
// §4.1.6) requests were rejected with "central key generation not supported"
// in production until this forwarder was added — this test exists so the
// next new optional CMP interface doesn't silently repeat the bug.
func TestDMSEventPublisher_ForwardsLWCValidateKGARecipient(t *testing.T) {
	inner := &kgaRecipientValidatingMock{MockDMSManagerService: new(svcmock.MockDMSManagerService)}
	wrapped := NewDMSEventPublisher(&CloudEventPublisherMock{})(inner)

	validator, ok := wrapped.(services.LightweightCMPKGARecipientValidator)
	require.True(t, ok, "dmsEventPublisher must forward services.LightweightCMPKGARecipientValidator to the wrapped service")

	err := validator.LWCValidateKGARecipient(context.Background(), "test-dms", &x509.Certificate{})
	assert.NoError(t, err)
	assert.True(t, inner.called, "the call must reach the wrapped service, not be swallowed")
}
