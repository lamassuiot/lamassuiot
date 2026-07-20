package cmp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	cmpwfx "github.com/lamassuiot/lamassuiot/backend/v3/pkg/integrations/wfx"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	cmpmock "github.com/lamassuiot/lamassuiot/core/v3/pkg/services/mock"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Shared test helpers (extracted to reduce duplication across the cmp test
// suite). All helpers preserve the exact byte layout / semantics of the
// per-file variants they replace.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// F1 — router/mock setup helpers.
//
// The three helpers below collapse the copy-pasted
//
//	svc := &cmpmock.MockLightweightCMPService{}
//	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").Return(&opts, nil)
//	svc.On("LWCEnroll"/"LWCReenroll", ...).Return(issued, nil)
//	router, store := newTestRouterWithStore(svc)
//
// stanza. They return the svc as well so callers that need additional mock
// expectations (extra .On(...) registrations, WFX reporters, error returns)
// can keep customising it.
// ---------------------------------------------------------------------------

// newOptionsRouter registers only LWCGetEnrollmentOptions for "test-dms".
func newOptionsRouter(t *testing.T, opts models.EnrollmentOptionsLWCRFC9483) (*gin.Engine, *inMemoryCMPStore, *cmpmock.MockLightweightCMPService) {
	t.Helper()
	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").Return(&opts, nil)
	router, store := newTestRouterWithStore(svc)
	return router, store, svc
}

// newEnrollRouter registers LWCGetEnrollmentOptions + LWCEnroll for "test-dms".
func newEnrollRouter(t *testing.T, opts models.EnrollmentOptionsLWCRFC9483, issued *x509.Certificate) (*gin.Engine, *inMemoryCMPStore, *cmpmock.MockLightweightCMPService) {
	t.Helper()
	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").Return(&opts, nil)
	svc.On("LWCEnroll", mock.Anything, mock.AnythingOfType("*x509.CertificateRequest"), "test-dms", mock.Anything).Return(issued, nil)
	router, store := newTestRouterWithStore(svc)
	return router, store, svc
}

// newReenrollRouter registers LWCGetEnrollmentOptions + LWCReenroll for "test-dms".
func newReenrollRouter(t *testing.T, opts models.EnrollmentOptionsLWCRFC9483, issued *x509.Certificate) (*gin.Engine, *inMemoryCMPStore, *cmpmock.MockLightweightCMPService) {
	t.Helper()
	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").Return(&opts, nil)
	svc.On("LWCReenroll", mock.Anything, mock.AnythingOfType("*x509.CertificateRequest"), "test-dms", mock.Anything).Return(issued, nil)
	router, store := newTestRouterWithStore(svc)
	return router, store, svc
}

// newEnrollRouterWFX is newEnrollRouter with a WFX reporter attached.
func newEnrollRouterWFX(t *testing.T, opts models.EnrollmentOptionsLWCRFC9483, issued *x509.Certificate, reporter cmpwfx.CMPReporter) (*gin.Engine, *inMemoryCMPStore, *cmpmock.MockLightweightCMPService) {
	t.Helper()
	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").Return(&opts, nil)
	svc.On("LWCEnroll", mock.Anything, mock.AnythingOfType("*x509.CertificateRequest"), "test-dms", mock.Anything).Return(issued, nil)
	router, store := newTestRouterWithStoreAndWFX(svc, reporter)
	return router, store, svc
}

// ---------------------------------------------------------------------------
// F2 — ASN.1 TLV builders.
// ---------------------------------------------------------------------------

// seqDER wraps the concatenation of content in a UNIVERSAL SEQUENCE (compound).
func seqDER(t *testing.T, content ...[]byte) []byte {
	t.Helper()
	der, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      concatBytes(content...),
	})
	require.NoError(t, err)
	return der
}

// ctxDER wraps the concatenation of content in a context-specific [tag] TLV
// (compound). It is only for the IsCompound:true case; callers that need a
// primitive context tag (e.g. raVerified [0] NULL) must build it inline.
func ctxDER(t *testing.T, tag int, content ...[]byte) []byte {
	t.Helper()
	der, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        tag,
		IsCompound: true,
		Bytes:      concatBytes(content...),
	})
	require.NoError(t, err)
	return der
}

// ---------------------------------------------------------------------------
// F3 — CertRequest / CertReqMsg body-builder core.
// ---------------------------------------------------------------------------

// buildCertTemplateDER encodes a CertTemplate SEQUENCE with subject [5] CN and
// subjectPublicKeyInfo [6] (content-only SPKI, as decodeFirstCertReq expects).
func buildCertTemplateDER(t *testing.T, cn string, pubKeyDER []byte) []byte {
	t.Helper()
	subjectField := ctxDER(t, 5, buildSubjectCN(t, cn))

	// [6] carries the CONTENT of the SubjectPublicKeyInfo SEQUENCE (no outer tag).
	var spkiRaw asn1.RawValue
	_, err := asn1.Unmarshal(pubKeyDER, &spkiRaw)
	require.NoError(t, err)
	pubKeyField := ctxDER(t, 6, spkiRaw.Bytes)

	return seqDER(t, subjectField, pubKeyField)
}

// buildCertRequestDER encodes CertRequest ::= SEQUENCE { certReqId INTEGER,
// certTemplate CertTemplate, controls? }. Any extra trailing DER (e.g. a
// controls SEQUENCE) is appended verbatim.
func buildCertRequestDER(t *testing.T, cn string, pubKeyDER []byte, extra ...[]byte) []byte {
	t.Helper()
	certReqIDDER, err := asn1.Marshal(0)
	require.NoError(t, err)
	parts := append([]byte{}, certReqIDDER...)
	parts = concatBytes(parts, buildCertTemplateDER(t, cn, pubKeyDER))
	for _, e := range extra {
		parts = concatBytes(parts, e)
	}
	return seqDER(t, parts)
}

// wrapCertReqMsgs wraps a single CertRequest (with optional trailing POPO DER)
// into a SEQUENCE OF CertReqMsg containing one CertReqMsg.
func wrapCertReqMsgs(t *testing.T, certRequestDER []byte, trailing ...[]byte) []byte {
	t.Helper()
	certReqMsg := seqDER(t, concatBytes(append([][]byte{certRequestDER}, trailing...)...))
	return seqDER(t, certReqMsg)
}

// ---------------------------------------------------------------------------
// F4 — response-header field walker.
// ---------------------------------------------------------------------------

// responseHeaderField walks a response PKIMessage header and returns the first
// context-specific field carrying the given tag (searched after the positional
// pvno/sender/recipient triple). ok is false when the field is absent.
func responseHeaderField(t *testing.T, responseDER []byte, tag int) (asn1.RawValue, bool) {
	t.Helper()
	type rawMsg struct {
		Header asn1.RawValue
		Body   asn1.RawValue
	}
	var msg rawMsg
	_, err := asn1.Unmarshal(responseDER, &msg)
	require.NoError(t, err, "response must be a valid DER PKIMessage")

	var headerSeq asn1.RawValue
	_, err = asn1.Unmarshal(msg.Header.FullBytes, &headerSeq)
	require.NoError(t, err)

	remaining := headerSeq.Bytes
	// Skip pvno, sender, recipient.
	for i := 0; i < 3; i++ {
		var f asn1.RawValue
		remaining, err = asn1.Unmarshal(remaining, &f)
		require.NoError(t, err)
	}
	for len(remaining) > 0 {
		var f asn1.RawValue
		remaining, err = asn1.Unmarshal(remaining, &f)
		require.NoError(t, err)
		if f.Class == asn1.ClassContextSpecific && f.Tag == tag {
			return f, true
		}
	}
	return asn1.RawValue{}, false
}

// responseHeaderOctetString returns the content of a [tag] EXPLICIT OCTET STRING
// header field (one level of unwrapping), or nil when absent.
func responseHeaderOctetString(t *testing.T, responseDER []byte, tag int) []byte {
	t.Helper()
	f, ok := responseHeaderField(t, responseDER, tag)
	if !ok {
		return nil
	}
	var inner []byte
	if _, err := asn1.Unmarshal(f.Bytes, &inner); err == nil {
		return inner
	}
	return nil
}

// ---------------------------------------------------------------------------
// F5 — random 16-byte identifiers.
// ---------------------------------------------------------------------------

// randomNonce returns 16 random bytes for use as a CMP nonce.
func randomNonce(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 16)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return b
}

// randomTxID returns 16 random bytes for use as a CMP transactionID.
func randomTxID(t *testing.T) []byte {
	t.Helper()
	return randomNonce(t)
}

// ---------------------------------------------------------------------------
// F6 — stored-transaction sentNonce lookup.
// ---------------------------------------------------------------------------

// peekSentNonce looks up the transaction the server persisted for txID and
// returns the server-chosen senderNonce (decoded from hex). It asserts the row
// exists — the server must echo this value as recipNonce in a certConf.
func peekSentNonce(t *testing.T, store *inMemoryCMPStore, txID []byte) []byte {
	t.Helper()
	storedTx, ok := store.Peek(hex.EncodeToString(txID))
	require.True(t, ok, "transaction must be stored")
	sentNonce, err := hex.DecodeString(storedTx.SentNonce)
	require.NoError(t, err)
	return sentNonce
}

// inMemoryCMPStore is a thread-safe in-memory CMPTransactionRepo for unit tests.
type inMemoryCMPStore struct {
	mu  sync.Mutex
	txs map[string]models.CMPTransaction
}

func newInMemoryCMPStore() *inMemoryCMPStore {
	return &inMemoryCMPStore{txs: make(map[string]models.CMPTransaction)}
}

func (s *inMemoryCMPStore) Exists(_ context.Context, id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.txs[id]
	return ok, nil
}

func (s *inMemoryCMPStore) Insert(_ context.Context, tx models.CMPTransaction) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.txs[tx.TransactionID]; exists {
		return errs.ErrCMPTransactionAlreadyExists
	}
	s.txs[tx.TransactionID] = tx
	return nil
}

func (s *inMemoryCMPStore) SelectAndDelete(_ context.Context, id string) (models.CMPTransaction, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, ok := s.txs[id]
	if !ok {
		return models.CMPTransaction{}, false, nil
	}
	delete(s.txs, id)
	return tx, true, nil
}

func (s *inMemoryCMPStore) Peek(id string) (models.CMPTransaction, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, ok := s.txs[id]
	return tx, ok
}

func (s *inMemoryCMPStore) Select(_ context.Context, id string) (models.CMPTransaction, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, ok := s.txs[id]
	if !ok {
		return models.CMPTransaction{}, false, nil
	}
	return tx, true, nil
}

func (s *inMemoryCMPStore) SelectIncludingExpired(_ context.Context, id string) (models.CMPTransaction, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, ok := s.txs[id]
	if !ok {
		return models.CMPTransaction{}, false, nil
	}
	return tx, true, nil
}

func (s *inMemoryCMPStore) UpdateState(_ context.Context, id string, state models.CMPTransactionState, cert *models.X509Certificate, errorMessage string, expiresAt time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, ok := s.txs[id]
	if !ok {
		// Mirror Postgres impl semantics: report not-updated, no error.
		return false, nil
	}
	tx.State = state
	tx.Certificate = cert
	tx.ErrorMessage = errorMessage
	tx.ExpiresAt = expiresAt
	s.txs[id] = tx
	return true, nil
}

func (s *inMemoryCMPStore) HasUnconfirmedReenrollment(_ context.Context, dmsID, supersededCertSerial string) (bool, error) {
	if supersededCertSerial == "" {
		return false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, tx := range s.txs {
		if tx.DMSID == dmsID && tx.SupersededCertSerial == supersededCertSerial &&
			tx.IsReenrollment && tx.State == models.CMPTransactionStateIssued &&
			time.Now().Before(tx.ExpiresAt) {
			return true, nil
		}
	}
	return false, nil
}

func (s *inMemoryCMPStore) HasAbandonedReenrollment(_ context.Context, dmsID, supersededCertSerial string) (bool, error) {
	if supersededCertSerial == "" {
		return false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, tx := range s.txs {
		if tx.DMSID == dmsID && tx.SupersededCertSerial == supersededCertSerial &&
			tx.IsReenrollment && tx.State == models.CMPTransactionStateRevoked {
			return true, nil
		}
	}
	return false, nil
}

func (s *inMemoryCMPStore) HasSeenRegToken(_ context.Context, dmsID, regToken string) (bool, error) {
	if regToken == "" {
		return false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, tx := range s.txs {
		if tx.DMSID == dmsID && tx.RegToken == regToken {
			return true, nil
		}
	}
	return false, nil
}

func (s *inMemoryCMPStore) SelectByCertSerial(_ context.Context, certSerialNumber string) (models.CMPTransaction, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, tx := range s.txs {
		if tx.CertSerialNumber == certSerialNumber {
			return tx, true, nil
		}
	}
	return models.CMPTransaction{}, false, nil
}

func (s *inMemoryCMPStore) SelectPending(_ context.Context, limit int) ([]models.CMPTransaction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]models.CMPTransaction, 0)
	for _, tx := range s.txs {
		if tx.State == models.CMPTransactionStatePending {
			out = append(out, tx)
			if limit > 0 && len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

func (s *inMemoryCMPStore) DeleteExpired(_ context.Context) error { return nil }

func (s *inMemoryCMPStore) Confirm(_ context.Context, id string) (models.CMPTransaction, models.CMPTransactionState, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, ok := s.txs[id]
	if !ok {
		return models.CMPTransaction{}, "", false, nil
	}
	prior := tx.State
	if tx.State != models.CMPTransactionStateIssued {
		return models.CMPTransaction{}, prior, false, nil
	}
	tx.State = models.CMPTransactionStateConfirmed
	tx.ConfirmedAt = time.Now()
	s.txs[id] = tx
	return tx, prior, true, nil
}

func (s *inMemoryCMPStore) MarkRevokedByCertSerial(_ context.Context, certSerial string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, tx := range s.txs {
		if tx.CertSerialNumber == certSerial && tx.State == models.CMPTransactionStateConfirmed {
			tx.State = models.CMPTransactionStateRevoked
			s.txs[id] = tx
		}
	}
	return nil
}

func (s *inMemoryCMPStore) SelectAllByDMS(_ context.Context, dmsID string, _ bool, applyFunc func(models.CMPTransaction), _ *resources.QueryParameters) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, tx := range s.txs {
		if tx.DMSID == dmsID {
			applyFunc(tx)
		}
	}
	return "", nil
}

func (s *inMemoryCMPStore) SelectExpiredIssued(_ context.Context, limit int) ([]models.CMPTransaction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []models.CMPTransaction
	for _, tx := range s.txs {
		if tx.State == models.CMPTransactionStateIssued && time.Now().After(tx.ExpiresAt) {
			out = append(out, tx)
			if limit > 0 && len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

func (s *inMemoryCMPStore) SelectExpiredPending(_ context.Context, limit int) ([]models.CMPTransaction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []models.CMPTransaction
	for _, tx := range s.txs {
		if tx.State == models.CMPTransactionStatePending && time.Now().After(tx.ExpiresAt) {
			out = append(out, tx)
			if limit > 0 && len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

func (s *inMemoryCMPStore) MarkRevokedByTransactionID(_ context.Context, transactionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, ok := s.txs[transactionID]
	if !ok {
		return nil
	}
	tx.State = models.CMPTransactionStateRevoked
	s.txs[transactionID] = tx
	return nil
}

// mockServiceWithStore wraps a MockLightweightCMPService and exposes a
// CMPTransactionRepo via cmpTransactionStorer so NewCMPHttpRoutes picks it up.
type mockServiceWithStore struct {
	*cmpmock.MockLightweightCMPService
	store storage.CMPTransactionRepo
}

func (m *mockServiceWithStore) GetCMPTransactionRepo() storage.CMPTransactionRepo { return m.store }

func newTestRouterWithStore(svc *cmpmock.MockLightweightCMPService) (*gin.Engine, *inMemoryCMPStore) {
	store := newInMemoryCMPStore()
	wrapped := &mockServiceWithStore{MockLightweightCMPService: svc, store: store}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	logger := logrus.NewEntry(logrus.New())
	routes, err := NewCMPHttpRoutes(logger, wrapped)
	if err != nil {
		panic(err)
	}
	r.POST("/.well-known/cmp/p/:id", routes.HandleCMP)
	return r, store
}

func newTestRouterWithStoreAndWFX(svc *cmpmock.MockLightweightCMPService, reporter cmpwfx.CMPReporter) (*gin.Engine, *inMemoryCMPStore) {
	store := newInMemoryCMPStore()
	wrapped := &mockServiceWithStoreAndWFX{MockLightweightCMPService: svc, store: store, wfx: reporter}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	logger := logrus.NewEntry(logrus.New())
	routes, err := NewCMPHttpRoutes(logger, wrapped)
	if err != nil {
		panic(err)
	}
	r.POST("/.well-known/cmp/p/:id", routes.HandleCMP)
	return r, store
}

func newTestRouterWithProtectionAndStore(svc *cmpmock.MockLightweightCMPServiceWithProtection) (*gin.Engine, *inMemoryCMPStore) {
	store := newInMemoryCMPStore()
	wrapped := &mockProtectionServiceWithStore{MockLightweightCMPServiceWithProtection: svc, store: store}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	logger := logrus.NewEntry(logrus.New())
	routes, err := NewCMPHttpRoutes(logger, wrapped)
	if err != nil {
		panic(err)
	}
	r.POST("/.well-known/cmp/p/:id", routes.HandleCMP)
	return r, store
}

// postCMP sends a DER-encoded PKIMessage to the test router and returns the response.
func postCMP(t *testing.T, router *gin.Engine, dmsID string, derMsg []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/.well-known/cmp/p/%s", dmsID),
		bytes.NewReader(derMsg))
	req.Header.Set("Content-Type", "application/pkixcmp")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// testIROptions controls what is included in a test IR PKIMessage.
type testIROptions struct {
	CN                  string
	TransactionID       []byte
	WithImplicitConfirm bool
	// POPOMode controls whether a proof-of-possession is included in the CertReqMsg.
	// ""           → no POPO (legacy behaviour)
	// "signature"  → valid POPOSigningKey self-signature with the new key
	// "badsig"     → POPOSigningKey with an incorrect signature
	// "raVerified" → raVerified [0] NULL
	POPOMode string
}

// buildTestIR constructs a minimal valid DER-encoded PKIMessage with an IR body.
func buildTestIR(t *testing.T, opts testIROptions) (derMsg []byte, txID []byte, privKey *ecdsa.PrivateKey) {
	t.Helper()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pubKeyDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	require.NoError(t, err)

	cn := opts.CN
	if cn == "" {
		cn = "test-device"
	}

	txID = opts.TransactionID
	if len(txID) == 0 {
		txID = randomTxID(t)
	}

	senderNonce := randomNonce(t)

	headerDER := buildTestPKIHeaderDER(t, txID, senderNonce, nil, opts.WithImplicitConfirm)
	bodyDER := buildTestIRBodyDERWithPOPO(t, cn, pubKeyDER, privKey, opts.POPOMode)

	msgDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      concatBytes(headerDER, bodyDER),
	})
	require.NoError(t, err)

	return msgDER, txID, privKey
}

// buildTestCertConf constructs a minimal DER-encoded certConf PKIMessage.
func buildTestCertConf(t *testing.T, txID []byte, certDER []byte, recipNonce []byte) []byte {
	t.Helper()

	senderNonce := randomNonce(t)

	headerDER := buildTestPKIHeaderDER(t, txID, senderNonce, recipNonce, false)

	hash := sha256.Sum256(certDER)
	certStatusDER, err := asn1.Marshal(struct {
		CertHash  []byte
		CertReqID int
	}{
		CertHash:  hash[:],
		CertReqID: 0,
	})
	require.NoError(t, err)

	certConfContent, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      certStatusDER,
	})
	require.NoError(t, err)

	// PKIBody certConf [24]
	bodyDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        cmpBodyTagCertConf,
		IsCompound: true,
		Bytes:      certConfContent,
	})
	require.NoError(t, err)

	msgDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      concatBytes(headerDER, bodyDER),
	})
	require.NoError(t, err)
	return msgDER
}

// messageTimeFieldDER encodes the messageTime [0] EXPLICIT GeneralizedTime
// PKIHeader field for when. RFC 9483 §3.1 makes messageTime mandatory, so
// every test header builder in this package includes one by default.
func messageTimeFieldDER(t *testing.T, when time.Time) []byte {
	t.Helper()
	inner, err := asn1.MarshalWithParams(when.UTC(), "generalized")
	require.NoError(t, err)
	field, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: inner,
	})
	require.NoError(t, err)
	return field
}

// buildTestPKIHeaderDER encodes a minimal PKIHeader SEQUENCE.
func buildTestPKIHeaderDER(t *testing.T, txID, senderNonce, recipNonce []byte, withImplicitConfirm bool) []byte {
	t.Helper()

	pvnoDER, err := asn1.Marshal(pvnoCMP2000)
	require.NoError(t, err)

	// Use an empty DirectoryName GeneralName [4] for sender/recipient.
	emptyName, err := asn1.Marshal(pkix.RDNSequence{})
	require.NoError(t, err)
	// DirectoryName is GeneralName [4] EXPLICIT Name
	senderDER, err := asn1.MarshalWithParams(asn1.RawValue{FullBytes: emptyName}, "tag:4")
	require.NoError(t, err)
	recipientDER := senderDER

	// messageTime [0] EXPLICIT GeneralizedTime — mandatory as of RFC 9483 §3.1;
	// every builder using this helper must carry a fresh one unless a test is
	// specifically exercising its absence (see buildTestPKIHeaderDERNoMessageTime).
	messageTimeDER := messageTimeFieldDER(t, time.Now())

	// transactionID [4] EXPLICIT OCTET STRING
	txIDInner, err := asn1.Marshal(txID)
	require.NoError(t, err)
	txIDField, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        4,
		IsCompound: true,
		Bytes:      txIDInner,
	})
	require.NoError(t, err)

	// senderNonce [5] EXPLICIT OCTET STRING
	nonceInner, err := asn1.Marshal(senderNonce)
	require.NoError(t, err)
	nonceField, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        5,
		IsCompound: true,
		Bytes:      nonceInner,
	})
	require.NoError(t, err)

	headerContent := concatBytes(pvnoDER, senderDER, recipientDER, messageTimeDER, txIDField, nonceField)

	if len(recipNonce) > 0 {
		recipNonceInner, err := asn1.Marshal(recipNonce)
		require.NoError(t, err)
		recipNonceField, err := asn1.Marshal(asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        6,
			IsCompound: true,
			Bytes:      recipNonceInner,
		})
		require.NoError(t, err)
		headerContent = append(headerContent, recipNonceField...)
	}

	if withImplicitConfirm {
		headerContent = append(headerContent, buildImplicitConfirmGeneralInfo(t)...)
	}

	headerDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      headerContent,
	})
	require.NoError(t, err)
	return headerDER
}

// buildImplicitConfirmGeneralInfo encodes generalInfo[8] with id-it-implicitConfirm.
func buildImplicitConfirmGeneralInfo(t *testing.T) []byte {
	t.Helper()

	// InfoTypeAndValue ::= SEQUENCE { infoType OID }  (value absent = implicit NULL per RFC 4210)
	infoTypeAndValue, err := asn1.Marshal(struct {
		OID asn1.ObjectIdentifier
	}{
		OID: oidImplicitConfirm,
	})
	require.NoError(t, err)

	// Wrap in SEQUENCE OF InfoTypeAndValue
	genInfoSeq, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      infoTypeAndValue,
	})
	require.NoError(t, err)

	// generalInfo [8] EXPLICIT
	genInfoField, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        8,
		IsCompound: true,
		Bytes:      genInfoSeq,
	})
	require.NoError(t, err)
	return genInfoField
}

// buildTestIRBodyDER encodes a minimal IR PKIBody (no POPO).
func buildTestIRBodyDER(t *testing.T, cn string, pubKeyDER []byte) []byte {
	t.Helper()
	return buildTestIRBodyDERWithPOPO(t, cn, pubKeyDER, nil, "")
}

// buildTestIRBodyDERWithPOPO encodes an IR PKIBody with optional POPO.
// popoMode: "" = no POPO, "signature" = valid, "badsig" = invalid, "raVerified" = [0] NULL.
func buildTestIRBodyDERWithPOPO(t *testing.T, cn string, pubKeyDER []byte, privKey *ecdsa.PrivateKey, popoMode string) []byte {
	t.Helper()

	certRequestDER := buildCertRequestDER(t, cn, pubKeyDER)

	// Build CertReqMsg trailing content: optional POPO after the CertRequest.
	var popo [][]byte

	switch popoMode {
	case "signature":
		// POPOSigningKey [1] IMPLICIT SEQUENCE { algId, signature }
		// The signature is over certRequestDER using the new private key.
		popo = append(popo, buildPOPOSigningKey(t, certRequestDER, privKey, false))
	case "badsig":
		// Same structure but with an intentionally wrong signature.
		popo = append(popo, buildPOPOSigningKey(t, certRequestDER, privKey, true))
	case "raVerified":
		// raVerified [0] NULL
		raVerified, err := asn1.Marshal(asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: false,
			Bytes:      []byte{}, // NULL
		})
		require.NoError(t, err)
		popo = append(popo, raVerified)
	case "":
		// No POPO — legacy behaviour.
	default:
		t.Fatalf("unknown popoMode %q", popoMode)
	}

	return ctxDER(t, cmpBodyTagIR, wrapCertReqMsgs(t, certRequestDER, popo...))
}

// buildSubjectCN encodes an RDNSequence with a single CN attribute.
func buildSubjectCN(t *testing.T, cn string) []byte {
	t.Helper()
	atv, err := asn1.Marshal(struct {
		Type  asn1.ObjectIdentifier
		Value interface{}
	}{
		Type:  asn1.ObjectIdentifier{2, 5, 4, 3},
		Value: asn1.RawValue{Tag: asn1.TagUTF8String, Bytes: []byte(cn)},
	})
	require.NoError(t, err)

	rdnDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      atv,
	})
	require.NoError(t, err)

	rdnSeqDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      rdnDER,
	})
	require.NoError(t, err)
	return rdnSeqDER
}

// buildSelfSignedCert generates a self-signed certificate for use in tests.
func buildSelfSignedCert(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Real EE certs carry a SubjectKeyIdentifier, and RFC 9483 §3.1 requires the
	// CMP senderKID to equal it; compute one (SHA-1 of the public key, RFC 5280
	// §4.2.1.2 method 1) so signed fixtures mirror production.
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	ski := sha1.Sum(pubDER)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		SubjectKeyId: ski[:],
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	return cert, key
}

// signCMPMessage adds ECDSA-SHA256 protection to a pre-built PKIMessage DER.
// Per RFC 4210 §5.1.3.1, the protectionAlg [1] field of the PKIHeader MUST
// be set when the message carries signature-based protection.
func signCMPMessage(t *testing.T, msgDER []byte, signerCert *x509.Certificate, signerKey crypto.Signer) []byte {
	t.Helper()

	var rawMsg rawPKIMessage
	_, err := asn1.Unmarshal(msgDER, &rawMsg)
	require.NoError(t, err)

	// Rewrite the sender [1] field to carry the signer certificate's Subject,
	// matching what production EEs must put on the wire: with signature-based
	// protection, RFC 9483 §3.5 requires the header sender to equal the
	// protection certificate's subject. The validator now enforces that, so
	// fixtures must mirror reality or every signed test would fail spuriously.
	headerDER := injectSenderInHeader(t, rawMsg.Header.FullBytes, signerCert.Subject)

	// Inject protectionAlg [1] EXPLICIT AlgorithmIdentifier into the header.
	// Peel the original header SEQUENCE and insert protectionAlg after the first
	// 3 mandatory fields (pvno, sender, recipient) per RFC 4210 §5.1.1.
	headerDER = injectProtectionAlgInHeader(t, headerDER,
		asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}) // ecdsaWithSHA256
	// RFC 9483 §3.1: signature-based protection MUST carry senderKID equal to the
	// protection cert's SubjectKeyIdentifier; the validator enforces it, so signed
	// fixtures must include it.
	headerDER = injectSenderKIDInHeader(t, headerDER, signerCert.SubjectKeyId)
	rawMsg.Header = asn1.RawValue{FullBytes: headerDER}

	payload, err := marshalProtectedPayload(headerDER, rawMsg.Body.FullBytes)
	require.NoError(t, err)

	digest := sha256.Sum256(payload)
	sig, err := signerKey.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)

	type fullMsg struct {
		Header     asn1.RawValue
		Body       asn1.RawValue
		Protection asn1.BitString  `asn1:"explicit,optional,tag:0,omitempty"`
		ExtraCerts []asn1.RawValue `asn1:"explicit,optional,tag:1,omitempty"`
	}
	protected := fullMsg{
		Header: rawMsg.Header,
		Body:   rawMsg.Body,
		Protection: asn1.BitString{
			Bytes:     sig,
			BitLength: len(sig) * 8,
		},
		ExtraCerts: []asn1.RawValue{{FullBytes: signerCert.Raw}},
	}

	out, err := asn1.Marshal(protected)
	require.NoError(t, err)
	return out
}

// corruptProtectionSignature flips a bit inside the Protection [0] BIT STRING
// of a DER-encoded PKIMessage so the EE-computed signature stops matching its
// own pubkey, while keeping all ASN.1 tags, lengths and lower-level structure
// valid. Used by tests that need to assert "signature verification failed"
// rather than "message could not be parsed".
func corruptProtectionSignature(t *testing.T, signedDER []byte) []byte {
	t.Helper()

	var outer asn1.RawValue
	_, err := asn1.Unmarshal(signedDER, &outer)
	require.NoError(t, err)
	require.Equal(t, asn1.TagSequence, outer.Tag, "expected outer SEQUENCE")

	// Walk fields of the outer SEQUENCE looking for [0] EXPLICIT (protection).
	remaining := outer.Bytes
	out := make([]byte, 0, len(signedDER))
	var rebuilt []byte
	flipped := false
	for len(remaining) > 0 {
		var field asn1.RawValue
		rest, err := asn1.Unmarshal(remaining, &field)
		require.NoError(t, err)
		consumed := len(remaining) - len(rest)

		if !flipped && field.Class == asn1.ClassContextSpecific && field.Tag == 0 {
			// field.FullBytes is the [0] EXPLICIT TLV; the last byte is the
			// last byte of the inner BIT STRING content (signature octet).
			// Flip it.
			mutated := make([]byte, len(field.FullBytes))
			copy(mutated, field.FullBytes)
			mutated[len(mutated)-1] ^= 0xFF
			rebuilt = append(rebuilt, mutated...)
			flipped = true
		} else {
			rebuilt = append(rebuilt, field.FullBytes...)
		}
		remaining = rest
		_ = consumed
	}
	require.True(t, flipped, "protection [0] field not found in signed PKIMessage")

	wrapped, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      rebuilt,
	})
	require.NoError(t, err)
	return append(out, wrapped...)
}

// parseCertRepRejection parses the first CertResponse from a CertRepMessage
// (ip/cp/kup body) and returns its statusString reason text and failInfo.
// Used to verify cert-request-level rejections that use ip/cp body instead
// of the error body type (RFC 9483 §4.1).
//
// Wire layout (DER):
//
//	PKIMessage SEQUENCE {
//	  header, body [tag] {
//	    CertRepMessage SEQUENCE {           ← certRepMsgSeq
//	      Responses SEQUENCE OF {           ← responsesSeq
//	        CertResponse SEQUENCE {         ← certRespSeq
//	          certReqId INTEGER,
//	          PKIStatusInfo SEQUENCE { ... }
//	        }
//	      }
//	    }
//	  }
//	}
func parseCertRepRejection(t *testing.T, responseDER []byte) (reason string, failInfo asn1.BitString) {
	t.Helper()
	var msg rawPKIMessage
	_, err := asn1.Unmarshal(responseDER, &msg)
	require.NoError(t, err, "response must be a valid DER PKIMessage")

	// msg.Body.Bytes = content inside [bodyTag]; first TLV is CertRepMessage SEQUENCE.
	var certRepMsgSeq asn1.RawValue
	_, err = asn1.Unmarshal(msg.Body.Bytes, &certRepMsgSeq)
	require.NoError(t, err, "parse CertRepMessage")

	// certRepMsgSeq.Bytes = Responses (SEQUENCE OF CertResponse).
	var responsesSeq asn1.RawValue
	_, err = asn1.Unmarshal(certRepMsgSeq.Bytes, &responsesSeq)
	require.NoError(t, err, "parse Responses SEQUENCE OF")

	// responsesSeq.Bytes = first CertResponse SEQUENCE.
	var certRespSeq asn1.RawValue
	_, err = asn1.Unmarshal(responsesSeq.Bytes, &certRespSeq)
	require.NoError(t, err, "parse CertResponse")

	// Inside CertResponse: certReqId INTEGER, PKIStatusInfo SEQUENCE.
	rest := certRespSeq.Bytes
	var certReqIDRaw asn1.RawValue
	rest, err = asn1.Unmarshal(rest, &certReqIDRaw)
	require.NoError(t, err, "parse certReqId")

	var psiRaw asn1.RawValue
	_, err = asn1.Unmarshal(rest, &psiRaw)
	require.NoError(t, err, "parse PKIStatusInfo")

	// Walk PKIStatusInfo: status INTEGER, statusString? SEQUENCE OF UTF8String, failInfo? BIT STRING
	psiContent := psiRaw.Bytes
	var statusRaw asn1.RawValue
	psiContent, err = asn1.Unmarshal(psiContent, &statusRaw)
	require.NoError(t, err, "parse status INTEGER")
	for len(psiContent) > 0 {
		var field asn1.RawValue
		psiContent, err = asn1.Unmarshal(psiContent, &field)
		if err != nil {
			break
		}
		if field.Tag == asn1.TagSequence && field.Class == asn1.ClassUniversal && len(reason) == 0 {
			reason = scanFirstUTF8String(field.Bytes)
		}
		if field.Tag == asn1.TagBitString && field.Class == asn1.ClassUniversal {
			_, _ = asn1.Unmarshal(field.FullBytes, &failInfo)
		}
	}
	return
}

// parseCMPResponseTag returns the body CHOICE tag from a DER-encoded PKIMessage.
func parseCMPResponseTag(t *testing.T, body []byte) int {
	t.Helper()
	var msg rawPKIMessage
	_, err := asn1.Unmarshal(body, &msg)
	require.NoError(t, err, "response must be a valid DER PKIMessage")
	return msg.Body.Tag
}

// parseCMPErrorReason scans the error body for the first UTF8String.
func parseCMPErrorReason(t *testing.T, body []byte) string {
	t.Helper()
	var msg rawPKIMessage
	_, err := asn1.Unmarshal(body, &msg)
	require.NoError(t, err)
	if msg.Body.Tag != cmpBodyTagError {
		return ""
	}
	return scanFirstUTF8String(msg.Body.Bytes)
}

// buildTestPollReq constructs a minimal DER-encoded pollReq PKIMessage carrying
// the given transactionID and certReqId. Used by the async-issuance / polling
// tests to exercise the controller's handlePoll dispatch.
func buildTestPollReq(t *testing.T, txID []byte, certReqID int) []byte {
	t.Helper()

	senderNonce := randomNonce(t)

	headerDER := buildTestPKIHeaderDER(t, txID, senderNonce, nil, false)

	type pollReqEntry struct {
		CertReqID int
	}
	// PollReqContent ::= SEQUENCE OF SEQUENCE { certReqId INTEGER }
	// Marshaling a slice directly produces SEQUENCE OF — no extra struct wrapper.
	pollReqContent, err := asn1.Marshal([]pollReqEntry{{CertReqID: certReqID}})
	require.NoError(t, err)

	// PKIBody pollReq [25] wraps the PollReqContent SEQUENCE TLV (matching the
	// EXPLICIT-style convention buildTestCertConf uses for [24]).
	bodyDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        cmpBodyTagPollReq,
		IsCompound: true,
		Bytes:      pollReqContent,
	})
	require.NoError(t, err)

	msgDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      concatBytes(headerDER, bodyDER),
	})
	require.NoError(t, err)
	return msgDER
}

// parseIPBodyStatus extracts the PKIStatus integer from the first CertResponse
// in an ip (tag 1) or cp (tag 3) response. The walk is:
//
//	PKIMessage → Body → CertRepMessage SEQUENCE → response SEQUENCE OF →
//	  first CertResponse SEQUENCE → certReqId INTEGER → PKIStatusInfo SEQUENCE →
//	  status INTEGER
//
// Returns the PKIStatus and whether a CertifiedKeyPair followed (so callers can
// distinguish "waiting + no cert" from "accepted + cert payload").
func parseIPBodyStatus(t *testing.T, responseDER []byte) (status int, hasCertifiedKeyPair bool) {
	t.Helper()
	type rawMsg struct {
		Header asn1.RawValue
		Body   asn1.RawValue
	}
	var msg rawMsg
	_, err := asn1.Unmarshal(responseDER, &msg)
	require.NoError(t, err)

	// Body content (after [1] / [3] is stripped) is the CertRepMessage SEQUENCE TLV.
	var certRepMsg asn1.RawValue
	_, err = asn1.Unmarshal(msg.Body.Bytes, &certRepMsg)
	require.NoError(t, err)
	require.Equal(t, asn1.TagSequence, certRepMsg.Tag)

	// response: SEQUENCE OF CertResponse
	var responseSeqOf asn1.RawValue
	_, err = asn1.Unmarshal(certRepMsg.Bytes, &responseSeqOf)
	require.NoError(t, err)

	// first CertResponse
	var firstResp asn1.RawValue
	_, err = asn1.Unmarshal(responseSeqOf.Bytes, &firstResp)
	require.NoError(t, err)

	// certReqId INTEGER, then PKIStatusInfo SEQUENCE, then optional CertifiedKeyPair.
	var certReqID int
	rest, err := asn1.Unmarshal(firstResp.Bytes, &certReqID)
	require.NoError(t, err)

	var statusInfo asn1.RawValue
	rest, err = asn1.Unmarshal(rest, &statusInfo)
	require.NoError(t, err)

	_, err = asn1.Unmarshal(statusInfo.Bytes, &status)
	require.NoError(t, err)

	hasCertifiedKeyPair = len(rest) > 0
	return status, hasCertifiedKeyPair
}

// concatBytes concatenates byte slices.
func concatBytes(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// injectProtectionAlgOID modifies a DER PKIMessage to set protectionAlg [1]
// in the PKIHeader to the given OID.
func injectProtectionAlgOID(t *testing.T, msgDER []byte, algOID asn1.ObjectIdentifier) []byte {
	t.Helper()

	var rawMsg rawPKIMessage
	_, err := asn1.Unmarshal(msgDER, &rawMsg)
	require.NoError(t, err)

	// Decode the existing header SEQUENCE content.
	var headerSeq asn1.RawValue
	_, err = asn1.Unmarshal(rawMsg.Header.FullBytes, &headerSeq)
	require.NoError(t, err)

	// Build protectionAlg [1] EXPLICIT AlgorithmIdentifier
	algID, err := asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: algOID})
	require.NoError(t, err)
	protAlgField, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        1,
		IsCompound: true,
		Bytes:      algID,
	})
	require.NoError(t, err)

	// Reassemble: pvno, sender, recipient, then protectionAlg, then remaining fields.
	// We need to peel off pvno, sender, recipient (first 3 TLVs) and inject protAlg after.
	remaining := headerSeq.Bytes
	var firstThree []byte
	for i := 0; i < 3; i++ {
		var field asn1.RawValue
		rest, e := asn1.Unmarshal(remaining, &field)
		require.NoError(t, e)
		firstThree = append(firstThree, field.FullBytes...)
		remaining = rest
	}

	newHeaderContent := concatBytes(firstThree, protAlgField, remaining)
	newHeaderDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      newHeaderContent,
	})
	require.NoError(t, err)

	newMsgDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      concatBytes(newHeaderDER, rawMsg.Body.FullBytes),
	})
	require.NoError(t, err)
	return newMsgDER
}
