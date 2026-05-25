package controllers

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	cmpmock "github.com/lamassuiot/lamassuiot/core/v3/pkg/services/mock"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Test infrastructure
// ---------------------------------------------------------------------------

// newTestRouter sets up a Gin test engine with the CMP handler bound to
// /.well-known/cmp/p/:id. The service has NO transaction store — suitable for
// tests that only exercise the immediate response path (e.g. protection
// verification that rejects before enrollment).
func newTestRouter(svc services.LightweightCMPService) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	logger := logrus.NewEntry(logrus.New())
	routes := NewCMPHttpRoutes(logger, svc)
	r.POST("/.well-known/cmp/p/:id", routes.HandleCMP)
	return r
}

// inMemoryCMPStore is a thread-safe in-memory CMPTransactionRepo for unit tests.
type inMemoryCMPStore struct {
	mu  sync.Mutex
	txs map[string]storage.CMPTransaction
}

func newInMemoryCMPStore() *inMemoryCMPStore {
	return &inMemoryCMPStore{txs: make(map[string]storage.CMPTransaction)}
}

func (s *inMemoryCMPStore) Exists(_ context.Context, id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.txs[id]
	return ok, nil
}

func (s *inMemoryCMPStore) Insert(_ context.Context, tx storage.CMPTransaction) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.txs[tx.TransactionID]; exists {
		return errs.ErrCMPTransactionAlreadyExists
	}
	s.txs[tx.TransactionID] = tx
	return nil
}

func (s *inMemoryCMPStore) SelectAndDelete(_ context.Context, id string) (storage.CMPTransaction, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, ok := s.txs[id]
	if !ok {
		return storage.CMPTransaction{}, false, nil
	}
	delete(s.txs, id)
	return tx, true, nil
}

func (s *inMemoryCMPStore) Peek(id string) (storage.CMPTransaction, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, ok := s.txs[id]
	return tx, ok
}

func (s *inMemoryCMPStore) Select(_ context.Context, id string) (storage.CMPTransaction, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, ok := s.txs[id]
	if !ok {
		return storage.CMPTransaction{}, false, nil
	}
	return tx, true, nil
}

func (s *inMemoryCMPStore) SelectIncludingExpired(_ context.Context, id string) (storage.CMPTransaction, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, ok := s.txs[id]
	if !ok {
		return storage.CMPTransaction{}, false, nil
	}
	return tx, true, nil
}

func (s *inMemoryCMPStore) UpdateState(_ context.Context, id string, state storage.CMPTransactionState, cert *models.X509Certificate, errorMessage string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, ok := s.txs[id]
	if !ok {
		// Mirror Postgres impl semantics: silent no-op when row is gone.
		return nil
	}
	tx.State = state
	tx.Certificate = cert
	tx.ErrorMessage = errorMessage
	s.txs[id] = tx
	return nil
}

func (s *inMemoryCMPStore) SelectPending(_ context.Context, limit int) ([]storage.CMPTransaction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]storage.CMPTransaction, 0)
	for _, tx := range s.txs {
		if tx.State == storage.CMPTransactionStatePending {
			out = append(out, tx)
			if limit > 0 && len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

func (s *inMemoryCMPStore) DeleteExpired(_ context.Context) error { return nil }

func (s *inMemoryCMPStore) Confirm(_ context.Context, id string) (storage.CMPTransaction, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, ok := s.txs[id]
	if !ok || tx.State != storage.CMPTransactionStateIssued {
		return storage.CMPTransaction{}, false, nil
	}
	tx.State = storage.CMPTransactionStateConfirmed
	tx.ConfirmedAt = time.Now()
	s.txs[id] = tx
	return tx, true, nil
}

func (s *inMemoryCMPStore) MarkRevokedByCertSerial(_ context.Context, certSerial string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, tx := range s.txs {
		if tx.CertSerialNumber == certSerial && tx.State == storage.CMPTransactionStateConfirmed {
			tx.State = storage.CMPTransactionStateRevoked
			s.txs[id] = tx
		}
	}
	return nil
}

func (s *inMemoryCMPStore) SelectAllByDMS(_ context.Context, dmsID string, _ bool, applyFunc func(storage.CMPTransaction), _ *resources.QueryParameters) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, tx := range s.txs {
		if tx.DMSID == dmsID {
			applyFunc(tx)
		}
	}
	return "", nil
}

func (s *inMemoryCMPStore) SelectExpiredIssued(_ context.Context, limit int) ([]storage.CMPTransaction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []storage.CMPTransaction
	for _, tx := range s.txs {
		if tx.State == storage.CMPTransactionStateIssued && time.Now().After(tx.ExpiresAt) {
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
	tx.State = storage.CMPTransactionStateRevoked
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
	routes := NewCMPHttpRoutes(logger, wrapped)
	r.POST("/.well-known/cmp/p/:id", routes.HandleCMP)
	return r, store
}

// mockProtectionServiceWithStore combines LightweightCMPProtectionProvider and
// cmpTransactionStorer for tests that exercise protected responses.
type mockProtectionServiceWithStore struct {
	*cmpmock.MockLightweightCMPServiceWithProtection
	store storage.CMPTransactionRepo
}

func (m *mockProtectionServiceWithStore) GetCMPTransactionRepo() storage.CMPTransactionRepo {
	return m.store
}

func newTestRouterWithProtectionAndStore(svc *cmpmock.MockLightweightCMPServiceWithProtection) (*gin.Engine, *inMemoryCMPStore) {
	store := newInMemoryCMPStore()
	wrapped := &mockProtectionServiceWithStore{MockLightweightCMPServiceWithProtection: svc, store: store}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	logger := logrus.NewEntry(logrus.New())
	routes := NewCMPHttpRoutes(logger, wrapped)
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

// ---------------------------------------------------------------------------
// PKIMessage builder helpers
// ---------------------------------------------------------------------------

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
		txID = make([]byte, 16)
		_, err = rand.Read(txID)
		require.NoError(t, err)
	}

	senderNonce := make([]byte, 16)
	_, err = rand.Read(senderNonce)
	require.NoError(t, err)

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

	senderNonce := make([]byte, 16)
	rand.Read(senderNonce)

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

	headerContent := concatBytes(pvnoDER, senderDER, recipientDER, txIDField, nonceField)

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

	subjectDER := buildSubjectCN(t, cn)

	subjectField, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        5,
		IsCompound: true,
		Bytes:      subjectDER,
	})
	require.NoError(t, err)

	// [6] must carry the CONTENT of the SubjectPublicKeyInfo SEQUENCE
	// (without the outer SEQUENCE tag), because decodeFirstCertReq calls
	// wrapSequenceDER on field.Bytes which re-adds the tag.
	var spkiRaw asn1.RawValue
	_, err = asn1.Unmarshal(pubKeyDER, &spkiRaw)
	require.NoError(t, err)

	pubKeyField, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        6,
		IsCompound: true,
		Bytes:      spkiRaw.Bytes, // content only, not full SEQUENCE DER
	})
	require.NoError(t, err)

	certTemplateDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      concatBytes(subjectField, pubKeyField),
	})
	require.NoError(t, err)

	certReqIDDER, err := asn1.Marshal(0)
	require.NoError(t, err)

	// CertRequest = SEQUENCE { certReqId INTEGER, certTemplate CertTemplate }
	certRequestDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      concatBytes(certReqIDDER, certTemplateDER),
	})
	require.NoError(t, err)

	// Build CertReqMsg content: CertRequest followed by optional POPO.
	certReqMsgContent := certRequestDER

	switch popoMode {
	case "signature":
		// POPOSigningKey [1] IMPLICIT SEQUENCE { algId, signature }
		// The signature is over certRequestDER using the new private key.
		popoDER := buildPOPOSigningKey(t, certRequestDER, privKey, false)
		certReqMsgContent = concatBytes(certReqMsgContent, popoDER)
	case "badsig":
		// Same structure but with an intentionally wrong signature.
		popoDER := buildPOPOSigningKey(t, certRequestDER, privKey, true)
		certReqMsgContent = concatBytes(certReqMsgContent, popoDER)
	case "raVerified":
		// raVerified [0] NULL
		raVerified, err := asn1.Marshal(asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: false,
			Bytes:      []byte{}, // NULL
		})
		require.NoError(t, err)
		certReqMsgContent = concatBytes(certReqMsgContent, raVerified)
	case "":
		// No POPO — legacy behaviour.
	default:
		t.Fatalf("unknown popoMode %q", popoMode)
	}

	certReqMsgDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      certReqMsgContent,
	})
	require.NoError(t, err)

	certReqMsgsDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      certReqMsgDER,
	})
	require.NoError(t, err)

	bodyDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        cmpBodyTagIR,
		IsCompound: true,
		Bytes:      certReqMsgsDER,
	})
	require.NoError(t, err)

	return bodyDER
}

// buildPOPOSigningKey builds a POPOSigningKey [1] for a CertReqMsg.
// POPOSigningKey ::= SEQUENCE { algorithmIdentifier AlgorithmIdentifier, signature BIT STRING }
// The signature is ECDSA-SHA256 over certRequestDER.
// If corrupt is true, the signature bytes are intentionally mangled.
func buildPOPOSigningKey(t *testing.T, certRequestDER []byte, privKey *ecdsa.PrivateKey, corrupt bool) []byte {
	t.Helper()

	// Sign certRequestDER with ECDSA-SHA256.
	digest := sha256.Sum256(certRequestDER)
	sig, err := privKey.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)

	if corrupt {
		// Flip some bytes to make it invalid.
		sig[0] ^= 0xFF
		sig[len(sig)-1] ^= 0xFF
	}

	// AlgorithmIdentifier for ecdsaWithSHA256
	algID, err := asn1.Marshal(pkix.AlgorithmIdentifier{
		Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2},
	})
	require.NoError(t, err)

	// BIT STRING signature
	sigBits, err := asn1.Marshal(asn1.BitString{Bytes: sig, BitLength: len(sig) * 8})
	require.NoError(t, err)

	// POPOSigningKey is [1] IMPLICIT SEQUENCE { algId, signature }
	// The context-specific tag 1 wraps the content of the SEQUENCE.
	popoDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        1,
		IsCompound: true,
		Bytes:      concatBytes(algID, sigBits),
	})
	require.NoError(t, err)

	return popoDER
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

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
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

	// Inject protectionAlg [1] EXPLICIT AlgorithmIdentifier into the header.
	// Peel the original header SEQUENCE and insert protectionAlg after the first
	// 3 mandatory fields (pvno, sender, recipient) per RFC 4210 §5.1.1.
	headerDER := injectProtectionAlgInHeader(t, rawMsg.Header.FullBytes,
		asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}) // ecdsaWithSHA256
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

// injectProtectionAlgInHeader inserts protectionAlg [1] EXPLICIT AlgorithmIdentifier
// into a DER-encoded PKIHeader SEQUENCE, right after the first 3 TLVs (pvno, sender,
// recipient). If protectionAlg [1] is already present, the header is returned unchanged.
func injectProtectionAlgInHeader(t *testing.T, headerDER []byte, algOID asn1.ObjectIdentifier) []byte {
	t.Helper()

	var headerSeq asn1.RawValue
	_, err := asn1.Unmarshal(headerDER, &headerSeq)
	require.NoError(t, err)

	// Peel off the first 3 mandatory fields.
	remaining := headerSeq.Bytes
	var firstThree []byte
	for i := 0; i < 3; i++ {
		var field asn1.RawValue
		rest, e := asn1.Unmarshal(remaining, &field)
		require.NoError(t, e)
		firstThree = append(firstThree, field.FullBytes...)
		remaining = rest
	}

	// Check if protectionAlg [1] is already present.
	if len(remaining) > 0 {
		var peek asn1.RawValue
		_, _ = asn1.Unmarshal(remaining, &peek)
		if peek.Class == asn1.ClassContextSpecific && peek.Tag == 1 {
			return headerDER // already has protectionAlg
		}
	}

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

	newContent := concatBytes(firstThree, protAlgField, remaining)
	newHeaderDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      newContent,
	})
	require.NoError(t, err)
	return newHeaderDER
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

func scanFirstUTF8String(der []byte) string {
	remaining := der
	for len(remaining) > 0 {
		var v asn1.RawValue
		rest, err := asn1.Unmarshal(remaining, &v)
		if err != nil {
			return ""
		}
		remaining = rest
		if v.Tag == asn1.TagUTF8String && v.Class == asn1.ClassUniversal {
			return string(v.Bytes)
		}
		if v.IsCompound {
			if s := scanFirstUTF8String(v.Bytes); s != "" {
				return s
			}
		}
	}
	return ""
}

// buildTestPollReq constructs a minimal DER-encoded pollReq PKIMessage carrying
// the given transactionID and certReqId. Used by the async-issuance / polling
// tests to exercise the controller's handlePoll dispatch.
func buildTestPollReq(t *testing.T, txID []byte, certReqID int) []byte {
	t.Helper()

	senderNonce := make([]byte, 16)
	_, err := rand.Read(senderNonce)
	require.NoError(t, err)

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

// parseResponseBodyTag returns the PKIBody CHOICE tag of a CMP response.
// Useful for asserting whether the server replied with ip/cp (1/3), pollRep (26),
// or an error (23).
func parseResponseBodyTag(t *testing.T, responseDER []byte) int {
	t.Helper()
	type rawMsg struct {
		Header asn1.RawValue
		Body   asn1.RawValue
	}
	var msg rawMsg
	_, err := asn1.Unmarshal(responseDER, &msg)
	require.NoError(t, err)
	return msg.Body.Tag
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

// parseExtraCertsCount counts the certs in the extraCerts field [1] of a PKIMessage.
func parseExtraCertsCount(t *testing.T, responseDER []byte) int {
	t.Helper()
	type fullPKIMsg struct {
		Header     asn1.RawValue
		Body       asn1.RawValue
		Protection asn1.RawValue   `asn1:"optional,explicit,tag:0"`
		ExtraCerts []asn1.RawValue `asn1:"optional,explicit,tag:1"`
	}
	var msg fullPKIMsg
	_, err := asn1.Unmarshal(responseDER, &msg)
	require.NoError(t, err)
	return len(msg.ExtraCerts)
}

// concatBytes concatenates byte slices.
func concatBytes(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// ---------------------------------------------------------------------------
// Cycle 1: implicitConfirm skips the transaction store
// ---------------------------------------------------------------------------

// TestHandleCMP_ImplicitConfirm_NoCertConf verifies the implicit certificate
// confirmation mechanism (RFC 4210 §5.3.2 / RFC 9483 §4.1.1).
//
// When the DMS is configured with IMPLICIT confirmation mode AND the EE
// includes id-it-implicitConfirm (OID 1.3.6.1.5.5.7.4.13) in its request
// generalInfo, the handler must:
//   - Still store an ISSUED row for lost-response recovery via pollReq.
//   - Include id-it-implicitConfirm in the response generalInfo.
//   - NOT set ResponseSenderNonce (no certConf round-trip expected).
//
// The EE receives its cert in IP and can use it immediately without a
// confirm round-trip. If the response is lost, pollReq retrieves the cert.
func TestHandleCMP_ImplicitConfirm_NoCertConf(t *testing.T) {
	issuedCert, _ := buildSelfSignedCert(t, "test-device")

	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(&models.EnrollmentOptionsLWCRFC9483{
			AcceptImplicit: true,
		}, nil)
	svc.On("LWCEnroll", mock.Anything, mock.AnythingOfType("*x509.CertificateRequest"), "test-dms").
		Return(issuedCert, nil)

	// Use a router WITH a store to verify the ISSUED row is created for
	// lost-response recovery even in implicit-confirm mode.
	router, store := newTestRouterWithStore(svc)
	txID := make([]byte, 16)
	rand.Read(txID)

	// Step 1: IR with id-it-implicitConfirm OID
	irDER, _, _ := buildTestIR(t, testIROptions{
		CN:                  "test-device",
		TransactionID:       txID,
		WithImplicitConfirm: true,
	})
	irResp := postCMP(t, router, "test-dms", irDER)
	require.Equal(t, http.StatusOK, irResp.Code)
	assert.Equal(t, cmpBodyTagIP, parseCMPResponseTag(t, irResp.Body.Bytes()),
		"ir with implicitConfirm must receive IP response")

	// Verify the ISSUED transaction WAS inserted for lost-response recovery.
	storedTx, found := store.Peek(hex.EncodeToString(txID))
	assert.True(t, found, "implicit confirm must still insert an ISSUED row for pollReq recovery")
	if found {
		assert.Equal(t, storage.CMPTransactionStateIssued, storedTx.State)
		assert.NotNil(t, storedTx.Certificate)
	}

	svc.AssertExpectations(t)
}

// TestHandleCMP_ExplicitConfirm_CertConfSucceeds verifies the baseline
// explicit confirmation flow (RFC 4210 §5.2.8):
//
//	ir → IP (enroll succeeds, transaction stored) → certConf (hash matches) → pkiConf
//
// The test validates:
//   - IR produces an IP response (tag 1).
//   - A pending transaction IS persisted in the store.
//   - certConf with the correct SHA-256 hash of the issued cert returns pkiConf (tag 19).
func TestHandleCMP_ExplicitConfirm_CertConfSucceeds(t *testing.T) {
	issuedCert, _ := buildSelfSignedCert(t, "test-device-explicit")

	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(&models.EnrollmentOptionsLWCRFC9483{AcceptImplicit: false}, nil)
	svc.On("LWCEnroll", mock.Anything, mock.AnythingOfType("*x509.CertificateRequest"), "test-dms").
		Return(issuedCert, nil)

	router, store := newTestRouterWithStore(svc)
	txID := make([]byte, 16)
	rand.Read(txID)

	irDER, _, _ := buildTestIR(t, testIROptions{CN: "test-device-explicit", TransactionID: txID})
	irResp := postCMP(t, router, "test-dms", irDER)
	require.Equal(t, http.StatusOK, irResp.Code)
	assert.Equal(t, cmpBodyTagIP, parseCMPResponseTag(t, irResp.Body.Bytes()))

	// Peek at the stored transaction to get the senderNonce the server chose,
	// which must be echoed back as recipNonce in the certConf (RFC 4210 §5.1.1).
	storedTx, ok := store.Peek(hex.EncodeToString(txID))
	require.True(t, ok, "transaction must be stored after explicit-mode IR")

	sentNonce, _ := hex.DecodeString(storedTx.SentNonce)
	certConfDER := buildTestCertConf(t, txID, issuedCert.Raw, sentNonce)
	confResp := postCMP(t, router, "test-dms", certConfDER)
	require.Equal(t, http.StatusOK, confResp.Code)
	assert.Equal(t, cmpBodyTagPKIConf, parseCMPResponseTag(t, confResp.Body.Bytes()),
		"certConf with correct hash must receive pkiConf")

	svc.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Cycle 2 & 3: EE signature-based protection verification
// ---------------------------------------------------------------------------

// TestHandleCMP_ProtectionVerification_ValidSignature verifies that a CMP
// message with valid ECDSA-SHA256 signature-based protection (RFC 4210 §5.1.3)
// is accepted by the handler. The protection is verified against the EE
// certificate in extraCerts[0]. With EnforceRequestProtection=false, a valid
// signature is accepted opportunistically but not required.
func TestHandleCMP_ProtectionVerification_ValidSignature(t *testing.T) {
	issuedCert, _ := buildSelfSignedCert(t, "device-sig-valid")
	signerCert, signerKey := buildSelfSignedCert(t, "device-signer")

	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(&models.EnrollmentOptionsLWCRFC9483{EnforceRequestProtection: false}, nil)
	svc.On("LWCEnroll", mock.Anything, mock.AnythingOfType("*x509.CertificateRequest"), "test-dms").
		Return(issuedCert, nil)

	router, _ := newTestRouterWithStore(svc)
	irDER, _, _ := buildTestIR(t, testIROptions{CN: "device-sig-valid"})
	signedIR := signCMPMessage(t, irDER, signerCert, signerKey)

	resp := postCMP(t, router, "test-dms", signedIR)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, cmpBodyTagIP, parseCMPResponseTag(t, resp.Body.Bytes()),
		"valid protection signature must yield IP response")

	svc.AssertExpectations(t)
}

// TestHandleCMP_ProtectionVerification_InvalidSignature verifies that when
// the protection field BIT STRING does not match the public key in
// extraCerts[0], the handler rejects the request with a CMP error body
// (tag 23) containing "protection" in the error text. LWCEnroll MUST NOT
// be called — signature verification is a pre-enrollment gate.
func TestHandleCMP_ProtectionVerification_InvalidSignature(t *testing.T) {
	signerCert, _ := buildSelfSignedCert(t, "device-signer")
	// wrongKey does not match signerCert.PublicKey — signature will be invalid.
	_, wrongKey := buildSelfSignedCert(t, "wrong-key")

	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(&models.EnrollmentOptionsLWCRFC9483{EnforceRequestProtection: false}, nil)
	// LWCEnroll must NOT be called when signature verification fails.

	router := newTestRouter(svc)
	irDER, _, _ := buildTestIR(t, testIROptions{CN: "device-bad-sig"})
	// signerCert goes into ExtraCerts, but wrongKey signs — mismatch → invalid.
	tamperedIR := signCMPMessage(t, irDER, signerCert, wrongKey)

	resp := postCMP(t, router, "test-dms", tamperedIR)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, cmpBodyTagError, parseCMPResponseTag(t, resp.Body.Bytes()),
		"tampered signature must return CMP error body")
	assert.Contains(t, parseCMPErrorReason(t, resp.Body.Bytes()), "protection",
		"error reason must mention protection failure")

	svc.AssertNotCalled(t, "LWCEnroll", mock.Anything, mock.Anything, mock.Anything)
}

// TestHandleCMP_ProtectionVerification_NoProtection verifies that an
// unprotected CMP message (no protection field, no extraCerts) is accepted
// when EnforceRequestProtection=false. In this mode, transport-layer mTLS
// is the authentication mechanism; message-level protection is optional.
func TestHandleCMP_ProtectionVerification_NoProtection(t *testing.T) {
	issuedCert, _ := buildSelfSignedCert(t, "device-no-prot")

	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(&models.EnrollmentOptionsLWCRFC9483{AcceptImplicit: false}, nil)
	svc.On("LWCEnroll", mock.Anything, mock.AnythingOfType("*x509.CertificateRequest"), "test-dms").
		Return(issuedCert, nil)

	router, _ := newTestRouterWithStore(svc)
	irDER, _, _ := buildTestIR(t, testIROptions{CN: "device-no-prot"})

	resp := postCMP(t, router, "test-dms", irDER)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, cmpBodyTagIP, parseCMPResponseTag(t, resp.Body.Bytes()),
		"unprotected message must be accepted when no signature is present")
}

// ---------------------------------------------------------------------------
// Cycle 4: extraCerts full chain in protected responses
// ---------------------------------------------------------------------------

// TestHandleCMP_Response_ExtraCertsContainsChain verifies that when the DMS
// implements LightweightCMPProtectionProvider and returns a multi-cert chain,
// ALL certificates (leaf + intermediates/root) are placed in the response
// extraCerts field. This allows EE clients to verify the RA’s signature
// without needing to pre-configure the entire trust chain locally.
func TestHandleCMP_Response_ExtraCertsContainsChain(t *testing.T) {
	issuedCert, _ := buildSelfSignedCert(t, "device-chain-test")
	leafCert, leafKey := buildSelfSignedCert(t, "cmp-protection-leaf")
	issuerCert, _ := buildSelfSignedCert(t, "cmp-protection-issuer")

	svc := &cmpmock.MockLightweightCMPServiceWithProtection{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(&models.EnrollmentOptionsLWCRFC9483{EnforceRequestProtection: false}, nil)
	svc.On("LWCEnroll", mock.Anything, mock.AnythingOfType("*x509.CertificateRequest"), "test-dms").
		Return(issuedCert, nil)
	// Protection provider returns a 2-cert chain: [leaf, issuer].
	svc.On("LWCProtectionCredentials", mock.Anything, "test-dms").
		Return([]*x509.Certificate{leafCert, issuerCert}, crypto.Signer(leafKey), nil)

	router, _ := newTestRouterWithProtectionAndStore(svc)
	irDER, _, _ := buildTestIR(t, testIROptions{CN: "device-chain-test"})

	resp := postCMP(t, router, "test-dms", irDER)
	require.Equal(t, http.StatusOK, resp.Code)

	extraCertsCount := parseExtraCertsCount(t, resp.Body.Bytes())
	assert.Equal(t, 2, extraCertsCount, "extraCerts must contain the full chain (leaf + issuer)")

	svc.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Cycle 5: EnforceRequestProtection
// ---------------------------------------------------------------------------

// TestHandleCMP_EnforceProtection_RejectsUnprotected verifies that when the
// DMS sets EnforceRequestProtection=true, any CMP message without a valid
// protection field is rejected with a CMP error (tag 23) mentioning
// "protection". This mode is used when the DMS requires message-level
// authentication and mTLS alone is not sufficient.
func TestHandleCMP_EnforceProtection_RejectsUnprotected(t *testing.T) {
	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(&models.EnrollmentOptionsLWCRFC9483{
			EnforceRequestProtection: true,
		}, nil)

	router, _ := newTestRouterWithStore(svc)
	irDER, _, _ := buildTestIR(t, testIROptions{CN: "device-no-prot-enforced"})

	resp := postCMP(t, router, "test-dms", irDER)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, cmpBodyTagError, parseCMPResponseTag(t, resp.Body.Bytes()),
		"unprotected request must be rejected when enforcement is enabled")
	assert.Contains(t, parseCMPErrorReason(t, resp.Body.Bytes()), "protection",
		"error reason must reference protection requirement")

	svc.AssertNotCalled(t, "LWCEnroll", mock.Anything, mock.Anything, mock.Anything)
}

// TestHandleCMP_EnforceProtection_AcceptsSignedRequest verifies that
// EnforceRequestProtection=true accepts a correctly signed message. This is
// the positive counterpart to TestHandleCMP_EnforceProtection_RejectsUnprotected
// — a valid ECDSA-SHA256 protection passes the gate and the enrollment proceeds.
func TestHandleCMP_EnforceProtection_AcceptsSignedRequest(t *testing.T) {
	issuedCert, _ := buildSelfSignedCert(t, "device-enforce-ok")
	signerCert, signerKey := buildSelfSignedCert(t, "signer-enforce-ok")

	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(&models.EnrollmentOptionsLWCRFC9483{
			EnforceRequestProtection: true,
		}, nil)
	svc.On("LWCEnroll", mock.Anything, mock.AnythingOfType("*x509.CertificateRequest"), "test-dms").
		Return(issuedCert, nil)

	router, _ := newTestRouterWithStore(svc)
	irDER, _, _ := buildTestIR(t, testIROptions{CN: "device-enforce-ok"})
	signedIR := signCMPMessage(t, irDER, signerCert, signerKey)

	resp := postCMP(t, router, "test-dms", signedIR)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, cmpBodyTagIP, parseCMPResponseTag(t, resp.Body.Bytes()),
		"signed request must be accepted when enforcement is enabled")

	svc.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Cycle 6: MAC-based protection OID rejection
// ---------------------------------------------------------------------------

// TestHandleCMP_MACProtection_Rejected verifies that MAC-based protection
// algorithms (id-PasswordBasedMac RFC 4210, id-DHBasedMac) are ALWAYS rejected
// regardless of EnforceRequestProtection. Only signature-based protection
// (RSA, ECDSA, Ed25519) is accepted. This prevents weaker shared-secret
// authentication from bypassing the PKI trust model.
func TestHandleCMP_MACProtection_Rejected(t *testing.T) {
	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(&models.EnrollmentOptionsLWCRFC9483{}, nil)

	router, _ := newTestRouterWithStore(svc)

	// Build a minimal IR with protectionAlg [1] set to id-PasswordBasedMac.
	irDER, _, _ := buildTestIR(t, testIROptions{CN: "device-mac"})
	irDERWithMACAlg := injectProtectionAlgOID(t, irDER, oidPasswordBasedMac)

	resp := postCMP(t, router, "test-dms", irDERWithMACAlg)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, cmpBodyTagError, parseCMPResponseTag(t, resp.Body.Bytes()),
		"MAC-based protection must be rejected")
	assert.Contains(t, parseCMPErrorReason(t, resp.Body.Bytes()), "MAC",
		"error reason must mention MAC rejection")

	svc.AssertNotCalled(t, "LWCEnroll", mock.Anything, mock.Anything, mock.Anything)
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

// ---------------------------------------------------------------------------
// Cycle 7: KUR (reenroll) flow
// ---------------------------------------------------------------------------

// TestHandleCMP_KUR_ExplicitConfirm verifies the full Key Update Request
// (reenroll) flow with explicit confirmation:
//
//	kur (tag 7) → kup (tag 8) → certConf (tag 24) → pkiConf (tag 19)
//
// KUR uses the same CertReqMessages structure as IR but with body tag 7.
// The handler routes to LWCReenroll instead of LWCEnroll.
func TestHandleCMP_KUR_ExplicitConfirm(t *testing.T) {
	issuedCert, _ := buildSelfSignedCert(t, "device-reenroll")

	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(&models.EnrollmentOptionsLWCRFC9483{AcceptImplicit: false}, nil)
	svc.On("LWCReenroll", mock.Anything, mock.AnythingOfType("*x509.CertificateRequest"), "test-dms").
		Return(issuedCert, nil)

	router, store := newTestRouterWithStore(svc)
	txID := make([]byte, 16)
	rand.Read(txID)

	// Build a KUR (tag 7) message — same CertReqMessages structure as IR but different tag.
	kurDER := buildTestKUR(t, testIROptions{CN: "device-reenroll", TransactionID: txID})
	kurResp := postCMP(t, router, "test-dms", kurDER)
	require.Equal(t, http.StatusOK, kurResp.Code)
	assert.Equal(t, cmpBodyTagKUP, parseCMPResponseTag(t, kurResp.Body.Bytes()),
		"kur must receive kup response")

	// Verify transaction was stored.
	storedTx, ok := store.Peek(hex.EncodeToString(txID))
	require.True(t, ok, "kur must store a pending transaction")

	// CertConf with correct hash.
	sentNonce, _ := hex.DecodeString(storedTx.SentNonce)
	certConfDER := buildTestCertConf(t, txID, issuedCert.Raw, sentNonce)
	confResp := postCMP(t, router, "test-dms", certConfDER)
	require.Equal(t, http.StatusOK, confResp.Code)
	assert.Equal(t, cmpBodyTagPKIConf, parseCMPResponseTag(t, confResp.Body.Bytes()),
		"certConf after kur must receive pkiConf")

	svc.AssertExpectations(t)
}

// TestHandleCMP_KUR_ImplicitConfirm verifies that the KUR code path also
// honours implicit confirmation: when the DMS is IMPLICIT and the EE includes
// id-it-implicitConfirm, kup is returned directly. An ISSUED row is still
// stored for lost-response recovery via pollReq.
func TestHandleCMP_KUR_ImplicitConfirm(t *testing.T) {
	issuedCert, _ := buildSelfSignedCert(t, "device-reenroll-implicit")

	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(&models.EnrollmentOptionsLWCRFC9483{AcceptImplicit: true}, nil)
	svc.On("LWCReenroll", mock.Anything, mock.AnythingOfType("*x509.CertificateRequest"), "test-dms").
		Return(issuedCert, nil)

	router, store := newTestRouterWithStore(svc)
	txID := make([]byte, 16)
	rand.Read(txID)

	kurDER := buildTestKUR(t, testIROptions{CN: "device-reenroll-implicit", TransactionID: txID, WithImplicitConfirm: true})
	kurResp := postCMP(t, router, "test-dms", kurDER)
	require.Equal(t, http.StatusOK, kurResp.Code)
	assert.Equal(t, cmpBodyTagKUP, parseCMPResponseTag(t, kurResp.Body.Bytes()),
		"implicit-confirm kur must receive kup response")

	// ISSUED row is stored for lost-response recovery even with implicit confirm.
	storedTx, found := store.Peek(hex.EncodeToString(txID))
	assert.True(t, found, "implicit confirm kur must still insert ISSUED row for pollReq recovery")
	if found {
		assert.Equal(t, storage.CMPTransactionStateIssued, storedTx.State)
		assert.NotNil(t, storedTx.Certificate)
	}

	svc.AssertExpectations(t)
}

// buildTestKUR constructs a minimal KUR PKIMessage (tag 7) from IR options.
func buildTestKUR(t *testing.T, opts testIROptions) []byte {
	t.Helper()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pubKeyDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	require.NoError(t, err)

	cn := opts.CN
	if cn == "" {
		cn = "test-device-kur"
	}
	txID := opts.TransactionID
	if len(txID) == 0 {
		txID = make([]byte, 16)
		rand.Read(txID)
	}

	senderNonce := make([]byte, 16)
	rand.Read(senderNonce)

	headerDER := buildTestPKIHeaderDER(t, txID, senderNonce, nil, opts.WithImplicitConfirm)

	// KUR body uses the same CertReqMessages structure as IR, but with tag 7.
	bodyContent := buildTestIRBodyContent(t, cn, pubKeyDER)
	bodyDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        cmpBodyTagKUR,
		IsCompound: true,
		Bytes:      bodyContent,
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

// buildTestIRBodyContent returns the inner CertReqMessages SEQUENCE bytes
// (without the outer body CHOICE tag wrapper) so callers can wrap it in IR (0)
// or KUR (7).
func buildTestIRBodyContent(t *testing.T, cn string, pubKeyDER []byte) []byte {
	t.Helper()

	subjectDER := buildSubjectCN(t, cn)

	subjectField, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        5,
		IsCompound: true,
		Bytes:      subjectDER,
	})
	require.NoError(t, err)

	var spkiRaw asn1.RawValue
	_, err = asn1.Unmarshal(pubKeyDER, &spkiRaw)
	require.NoError(t, err)

	pubKeyField, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        6,
		IsCompound: true,
		Bytes:      spkiRaw.Bytes,
	})
	require.NoError(t, err)

	certTemplateDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      concatBytes(subjectField, pubKeyField),
	})
	require.NoError(t, err)

	certReqIDDER, err := asn1.Marshal(0)
	require.NoError(t, err)

	certRequestDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      concatBytes(certReqIDDER, certTemplateDER),
	})
	require.NoError(t, err)

	certReqMsgDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      certRequestDER,
	})
	require.NoError(t, err)

	certReqMsgsDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      certReqMsgDER,
	})
	require.NoError(t, err)

	return certReqMsgsDER
}

// ---------------------------------------------------------------------------
// Cycle 8: duplicate transactionID rejection
// ---------------------------------------------------------------------------

// TestHandleCMP_DuplicateTransactionID verifies the replay-attack prevention
// mechanism (RFC 4210 §3.1 "transactionIdInUse"): a second IR carrying the
// same transactionID is rejected while the first is still pending certConf.
// This prevents duplicate certificate issuance from retransmitted requests.
func TestHandleCMP_DuplicateTransactionID(t *testing.T) {
	issuedCert, _ := buildSelfSignedCert(t, "device-dup-tx")

	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(&models.EnrollmentOptionsLWCRFC9483{AcceptImplicit: false}, nil)
	svc.On("LWCEnroll", mock.Anything, mock.AnythingOfType("*x509.CertificateRequest"), "test-dms").
		Return(issuedCert, nil)

	router, _ := newTestRouterWithStore(svc)
	txID := make([]byte, 16)
	rand.Read(txID)

	// First IR succeeds.
	ir1, _, _ := buildTestIR(t, testIROptions{CN: "device-dup-tx", TransactionID: txID})
	resp1 := postCMP(t, router, "test-dms", ir1)
	require.Equal(t, http.StatusOK, resp1.Code)
	assert.Equal(t, cmpBodyTagIP, parseCMPResponseTag(t, resp1.Body.Bytes()))

	// Second IR with same txID rejected.
	ir2, _, _ := buildTestIR(t, testIROptions{CN: "device-dup-tx-2", TransactionID: txID})
	resp2 := postCMP(t, router, "test-dms", ir2)
	require.Equal(t, http.StatusOK, resp2.Code)
	assert.Equal(t, cmpBodyTagError, parseCMPResponseTag(t, resp2.Body.Bytes()),
		"duplicate transactionID must be rejected")
	assert.Contains(t, parseCMPErrorReason(t, resp2.Body.Bytes()), "transactionID already in use")
}

// ---------------------------------------------------------------------------
// Cycle 9: certConf with wrong certHash
// ---------------------------------------------------------------------------

// TestHandleCMP_CertConf_WrongHash verifies the integrity check in certConf
// processing (RFC 4210 §5.2.8): when the SHA-256 certHash in the client’s
// certConf message does NOT match the hash of the issued certificate stored
// server-side, the handler returns a CMP error with "certHash mismatch".
// This detects certificate corruption or man-in-the-middle attacks.
func TestHandleCMP_CertConf_WrongHash(t *testing.T) {
	issuedCert, _ := buildSelfSignedCert(t, "device-wrong-hash")
	wrongCert, _ := buildSelfSignedCert(t, "wrong-cert")

	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(&models.EnrollmentOptionsLWCRFC9483{AcceptImplicit: false}, nil)
	svc.On("LWCEnroll", mock.Anything, mock.AnythingOfType("*x509.CertificateRequest"), "test-dms").
		Return(issuedCert, nil)

	router, store := newTestRouterWithStore(svc)
	txID := make([]byte, 16)
	rand.Read(txID)

	irDER, _, _ := buildTestIR(t, testIROptions{CN: "device-wrong-hash", TransactionID: txID})
	irResp := postCMP(t, router, "test-dms", irDER)
	require.Equal(t, http.StatusOK, irResp.Code)
	assert.Equal(t, cmpBodyTagIP, parseCMPResponseTag(t, irResp.Body.Bytes()))

	storedTx, ok := store.Peek(hex.EncodeToString(txID))
	require.True(t, ok)

	// Build certConf with hash of wrongCert — mismatch.
	sentNonce, _ := hex.DecodeString(storedTx.SentNonce)
	certConfDER := buildTestCertConf(t, txID, wrongCert.Raw, sentNonce)
	confResp := postCMP(t, router, "test-dms", certConfDER)
	require.Equal(t, http.StatusOK, confResp.Code)
	assert.Equal(t, cmpBodyTagError, parseCMPResponseTag(t, confResp.Body.Bytes()),
		"wrong certHash must be rejected")
	assert.Contains(t, parseCMPErrorReason(t, confResp.Body.Bytes()), "certHash mismatch")
}

// ---------------------------------------------------------------------------
// Cycle 10: unsupported body tag rejection
// ---------------------------------------------------------------------------

// TestHandleCMP_UnsupportedBodyTag verifies that any body CHOICE tag not
// handled by the dispatcher (i.e. not ir/cr/kur/rr/certConf) returns a CMP
// error body (tag 23) with "unsupported body tag". This covers
// forward-compatibility: new RFC body types are safely rejected until
// explicitly implemented.
func TestHandleCMP_UnsupportedBodyTag(t *testing.T) {
	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(&models.EnrollmentOptionsLWCRFC9483{}, nil)

	router, _ := newTestRouterWithStore(svc)

	// Build a message with body tag 99 (completely unsupported).
	txID := make([]byte, 16)
	rand.Read(txID)
	senderNonce := make([]byte, 16)
	rand.Read(senderNonce)
	headerDER := buildTestPKIHeaderDER(t, txID, senderNonce, nil, false)

	bodyDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        99,
		IsCompound: true,
		Bytes:      []byte{0x05, 0x00}, // NULL payload
	})
	require.NoError(t, err)

	msgDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      concatBytes(headerDER, bodyDER),
	})
	require.NoError(t, err)

	resp := postCMP(t, router, "test-dms", msgDER)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, cmpBodyTagError, parseCMPResponseTag(t, resp.Body.Bytes()),
		"unsupported body tag must return CMP error")
	assert.Contains(t, parseCMPErrorReason(t, resp.Body.Bytes()), "unsupported body tag")
}

// ---------------------------------------------------------------------------
// Cycle 11: certConf recipNonce mismatch
// ---------------------------------------------------------------------------

// TestHandleCMP_CertConf_RecipNonceMismatch verifies RFC 4210 §5.1.1 nonce
// replay protection: the EE’s certConf MUST echo the server’s previous
// senderNonce as recipNonce. When the nonces do not match, the handler
// rejects with "recipNonce mismatch", preventing replay of captured responses.
func TestHandleCMP_CertConf_RecipNonceMismatch(t *testing.T) {
	issuedCert, _ := buildSelfSignedCert(t, "device-nonce-mismatch")

	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(&models.EnrollmentOptionsLWCRFC9483{AcceptImplicit: false}, nil)
	svc.On("LWCEnroll", mock.Anything, mock.AnythingOfType("*x509.CertificateRequest"), "test-dms").
		Return(issuedCert, nil)

	router, _ := newTestRouterWithStore(svc)
	txID := make([]byte, 16)
	rand.Read(txID)

	irDER, _, _ := buildTestIR(t, testIROptions{CN: "device-nonce-mismatch", TransactionID: txID})
	irResp := postCMP(t, router, "test-dms", irDER)
	require.Equal(t, http.StatusOK, irResp.Code)
	assert.Equal(t, cmpBodyTagIP, parseCMPResponseTag(t, irResp.Body.Bytes()))

	// Build certConf with a random (wrong) recipNonce.
	wrongNonce := make([]byte, 16)
	rand.Read(wrongNonce)
	certConfDER := buildTestCertConf(t, txID, issuedCert.Raw, wrongNonce)
	confResp := postCMP(t, router, "test-dms", certConfDER)
	require.Equal(t, http.StatusOK, confResp.Code)
	assert.Equal(t, cmpBodyTagError, parseCMPResponseTag(t, confResp.Body.Bytes()),
		"wrong recipNonce must be rejected")
	assert.Contains(t, parseCMPErrorReason(t, confResp.Body.Bytes()), "recipNonce mismatch")
}

// ---------------------------------------------------------------------------
// Cycle 12: Revocation Request (rr → rp)
// ---------------------------------------------------------------------------

// TestHandleCMP_RR_Success verifies the happy-path revocation request flow
// (RFC 4210 §5.3.9): a valid rr (tag 11) carrying a known serial number and
// CRL reason triggers LWCRevokeCertificate and returns an rp (tag 12)
// response with PKIStatus=accepted (0).
func TestHandleCMP_RR_Success(t *testing.T) {
	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(&models.EnrollmentOptionsLWCRFC9483{}, nil)
	svc.On("LWCRevokeCertificate", mock.Anything, mock.MatchedBy(func(input services.RevokeCertificateInput) bool {
		return input.APS == "test-dms" && input.Reason == models.RevocationReason(1) // KeyCompromise
	})).Return(nil)

	router, _ := newTestRouterWithStore(svc)

	serial := big.NewInt(0x1234ABCD)
	rrDER := buildTestRR(t, serial, 1) // reason=1 (KeyCompromise)

	resp := postCMP(t, router, "test-dms", rrDER)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, cmpBodyTagRP, parseCMPResponseTag(t, resp.Body.Bytes()),
		"valid rr must receive rp response")

	svc.AssertExpectations(t)
}

// TestHandleCMP_RR_ServiceError verifies that when the downstream
// LWCRevokeCertificate returns an error (e.g. certificate not found, already
// revoked), the CMP handler propagates it as a CMP error body (tag 23)
// containing the service error text.
func TestHandleCMP_RR_ServiceError(t *testing.T) {
	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(&models.EnrollmentOptionsLWCRFC9483{}, nil)
	svc.On("LWCRevokeCertificate", mock.Anything, mock.Anything).
		Return(fmt.Errorf("certificate not found"))

	router, _ := newTestRouterWithStore(svc)

	serial := big.NewInt(0xDEAD)
	rrDER := buildTestRR(t, serial, 0)

	resp := postCMP(t, router, "test-dms", rrDER)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, cmpBodyTagError, parseCMPResponseTag(t, resp.Body.Bytes()),
		"failed revocation must return CMP error")
	assert.Contains(t, parseCMPErrorReason(t, resp.Body.Bytes()), "certificate not found")
}

// TestHandleCMP_RR_DefaultReason verifies that when the rr body’s
// crlEntryDetails extensions are absent (no CRL reason OID), the revocation
// reason defaults to 0 (Unspecified) per RFC 5280 §5.3.1.
func TestHandleCMP_RR_DefaultReason(t *testing.T) {
	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(&models.EnrollmentOptionsLWCRFC9483{}, nil)
	svc.On("LWCRevokeCertificate", mock.Anything, mock.MatchedBy(func(input services.RevokeCertificateInput) bool {
		return input.Reason == models.RevocationReason(0) // Unspecified
	})).Return(nil)

	router, _ := newTestRouterWithStore(svc)

	serial := big.NewInt(42)
	rrDER := buildTestRRNoReason(t, serial) // no crlEntryDetails

	resp := postCMP(t, router, "test-dms", rrDER)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, cmpBodyTagRP, parseCMPResponseTag(t, resp.Body.Bytes()))

	svc.AssertExpectations(t)
}

// buildTestRR constructs a DER-encoded PKIMessage with an rr (tag 11) body
// carrying a CertTemplate with the given serial number and a CRL reason extension.
func buildTestRR(t *testing.T, serial *big.Int, reason int) []byte {
	t.Helper()

	txID := make([]byte, 16)
	rand.Read(txID)
	senderNonce := make([]byte, 16)
	rand.Read(senderNonce)

	headerDER := buildTestPKIHeaderDER(t, txID, senderNonce, nil, false)
	bodyDER := buildTestRRBodyDER(t, serial, &reason)

	msgDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      concatBytes(headerDER, bodyDER),
	})
	require.NoError(t, err)
	return msgDER
}

// buildTestRRNoReason constructs an rr PKIMessage without crlEntryDetails.
func buildTestRRNoReason(t *testing.T, serial *big.Int) []byte {
	t.Helper()

	txID := make([]byte, 16)
	rand.Read(txID)
	senderNonce := make([]byte, 16)
	rand.Read(senderNonce)

	headerDER := buildTestPKIHeaderDER(t, txID, senderNonce, nil, false)
	bodyDER := buildTestRRBodyDER(t, serial, nil)

	msgDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      concatBytes(headerDER, bodyDER),
	})
	require.NoError(t, err)
	return msgDER
}

// buildTestRRBodyDER encodes an rr PKIBody (tag 11).
// RevReqContent ::= SEQUENCE OF RevDetails
// RevDetails    ::= SEQUENCE { certDetails CertTemplate, crlEntryDetails Extensions OPTIONAL }
// CertTemplate fields: serialNumber [1]
func buildTestRRBodyDER(t *testing.T, serial *big.Int, reason *int) []byte {
	t.Helper()

	// Encode serialNumber as INTEGER.
	serialDER, err := asn1.Marshal(serial)
	require.NoError(t, err)
	// Wrap as CertTemplate [1] IMPLICIT serialNumber.
	serialField, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        1,
		IsCompound: true,
		Bytes:      serialDER,
	})
	require.NoError(t, err)

	certTemplateContent := serialField

	certTemplateDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      certTemplateContent,
	})
	require.NoError(t, err)

	revDetailsContent := certTemplateDER

	// Optionally add crlEntryDetails Extensions.
	if reason != nil {
		extDER := buildCRLReasonExtension(t, *reason)
		revDetailsContent = append(revDetailsContent, extDER...)
	}

	revDetailsDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      revDetailsContent,
	})
	require.NoError(t, err)

	// SEQUENCE OF RevDetails (single entry)
	revReqContentDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      revDetailsDER,
	})
	require.NoError(t, err)

	// PKIBody rr [11]
	bodyDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        cmpBodyTagRR,
		IsCompound: true,
		Bytes:      revReqContentDER,
	})
	require.NoError(t, err)
	return bodyDER
}

// ---------------------------------------------------------------------------
// Cycle 13: POPO for IR/CR — valid signature
// ---------------------------------------------------------------------------

// TestHandleCMP_POPO_ValidSignature verifies Proof-of-Possession via
// POPOSigningKey [1] (RFC 4211 §4.1 clause 3): the EE creates a CRMF
// self-signature over the CertRequest using its new private key. When
// EnforcePOPO=true and the signature is correct, enrollment proceeds.
func TestHandleCMP_POPO_ValidSignature(t *testing.T) {
	issuedCert, _ := buildSelfSignedCert(t, "device-popo-valid")

	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(&models.EnrollmentOptionsLWCRFC9483{
			EnforcePOPO:    true,
			AcceptImplicit: true,
		}, nil)
	svc.On("LWCEnroll", mock.Anything, mock.AnythingOfType("*x509.CertificateRequest"), "test-dms").
		Return(issuedCert, nil)

	router, _ := newTestRouterWithStore(svc)
	irDER, _, _ := buildTestIR(t, testIROptions{
		CN:                  "device-popo-valid",
		WithImplicitConfirm: true,
		POPOMode:            "signature",
	})

	resp := postCMP(t, router, "test-dms", irDER)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, cmpBodyTagIP, parseCMPResponseTag(t, resp.Body.Bytes()),
		"IR with valid POPO signature must be accepted")

	svc.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Cycle 14: POPO for IR/CR — invalid signature
// ---------------------------------------------------------------------------

// TestHandleCMP_POPO_InvalidSignature verifies that a corrupt POPOSigningKey
// signature (bytes flipped) is detected and rejected. The error message
// references "proof of possession" and LWCEnroll is NEVER invoked, ensuring
// no certificate is issued for a key the requester does not actually hold.
func TestHandleCMP_POPO_InvalidSignature(t *testing.T) {
	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(&models.EnrollmentOptionsLWCRFC9483{
			EnforcePOPO:    true,
			AcceptImplicit: true,
		}, nil)

	router, _ := newTestRouterWithStore(svc)
	irDER, _, _ := buildTestIR(t, testIROptions{
		CN:                  "device-popo-badsig",
		WithImplicitConfirm: true,
		POPOMode:            "badsig",
	})

	resp := postCMP(t, router, "test-dms", irDER)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, cmpBodyTagError, parseCMPResponseTag(t, resp.Body.Bytes()),
		"IR with corrupt POPO signature must be rejected")
	assert.Contains(t, parseCMPErrorReason(t, resp.Body.Bytes()), "proof of possession",
		"error must reference POPO failure")

	svc.AssertNotCalled(t, "LWCEnroll", mock.Anything, mock.Anything, mock.Anything)
}

// ---------------------------------------------------------------------------
// Cycle 15: POPO absent + EnforcePOPO=true → rejected
// ---------------------------------------------------------------------------

// TestHandleCMP_POPO_Absent_Enforced verifies that when EnforcePOPO=true and
// the IR contains no ProofOfPossession field at all, the request is rejected.
// This catches misconfigured clients that send bare CertReqMessages without
// the CRMF self-signature, which would otherwise allow certificate issuance
// for keys the client may not possess.
func TestHandleCMP_POPO_Absent_Enforced(t *testing.T) {
	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(&models.EnrollmentOptionsLWCRFC9483{
			EnforcePOPO:    true,
			AcceptImplicit: true,
		}, nil)

	router, _ := newTestRouterWithStore(svc)
	irDER, _, _ := buildTestIR(t, testIROptions{
		CN:                  "device-popo-absent",
		WithImplicitConfirm: true,
		POPOMode:            "", // no POPO
	})

	resp := postCMP(t, router, "test-dms", irDER)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, cmpBodyTagError, parseCMPResponseTag(t, resp.Body.Bytes()),
		"IR without POPO must be rejected when EnforcePOPO=true")
	assert.Contains(t, parseCMPErrorReason(t, resp.Body.Bytes()), "proof of possession",
		"error must reference POPO requirement")

	svc.AssertNotCalled(t, "LWCEnroll", mock.Anything, mock.Anything, mock.Anything)
}

// ---------------------------------------------------------------------------
// Cycle 16: POPO absent + EnforcePOPO=false → accepted
// ---------------------------------------------------------------------------

// TestHandleCMP_POPO_Absent_NotEnforced verifies the default mode: when
// EnforcePOPO=false (Go zero value), an IR without any POPO field is accepted
// because possession is proven at the transport layer (mTLS client cert).
func TestHandleCMP_POPO_Absent_NotEnforced(t *testing.T) {
	issuedCert, _ := buildSelfSignedCert(t, "device-popo-notenforced")

	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(&models.EnrollmentOptionsLWCRFC9483{
			EnforcePOPO:    false,
			AcceptImplicit: true,
		}, nil)
	svc.On("LWCEnroll", mock.Anything, mock.AnythingOfType("*x509.CertificateRequest"), "test-dms").
		Return(issuedCert, nil)

	router, _ := newTestRouterWithStore(svc)
	irDER, _, _ := buildTestIR(t, testIROptions{
		CN:                  "device-popo-notenforced",
		WithImplicitConfirm: true,
		POPOMode:            "", // no POPO
	})

	resp := postCMP(t, router, "test-dms", irDER)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, cmpBodyTagIP, parseCMPResponseTag(t, resp.Body.Bytes()),
		"IR without POPO must be accepted when EnforcePOPO=false")

	svc.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Cycle 17: POPO raVerified → always accepted
// ---------------------------------------------------------------------------

// TestHandleCMP_POPO_RAVerified verifies that raVerified [0] POPO is accepted
// even when EnforcePOPO=true. Per RFC 4211 §4.3, raVerified means an upstream
// Registration Authority already proved possession; the RA MUST be trusted so
// the CA does not re-verify. This enables delegated enrollment flows.
func TestHandleCMP_POPO_RAVerified(t *testing.T) {
	issuedCert, _ := buildSelfSignedCert(t, "device-popo-raverified")

	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(&models.EnrollmentOptionsLWCRFC9483{
			EnforcePOPO:    true,
			AcceptImplicit: true,
		}, nil)
	svc.On("LWCEnroll", mock.Anything, mock.AnythingOfType("*x509.CertificateRequest"), "test-dms").
		Return(issuedCert, nil)

	router, _ := newTestRouterWithStore(svc)
	irDER, _, _ := buildTestIR(t, testIROptions{
		CN:                  "device-popo-raverified",
		WithImplicitConfirm: true,
		POPOMode:            "raVerified",
	})

	resp := postCMP(t, router, "test-dms", irDER)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, cmpBodyTagIP, parseCMPResponseTag(t, resp.Body.Bytes()),
		"IR with raVerified POPO must be accepted (upstream RA proved possession)")

	svc.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Cycle 18: KUR + EnforcePOPO=true → unprotected rejected (RFC 9483 §4.1.3)
// ---------------------------------------------------------------------------

// TestHandleCMP_KUR_EnforcePOPO_RejectsUnprotected verifies the RFC 9483
// §4.1.3 rule for KUR: the message-level protection IS the proof of
// possession (the old cert key signs the message). When EnforcePOPO=true
// but no protectionAlg is present in the header, the KUR is rejected
// because there is no other way to prove the client holds the old key.
func TestHandleCMP_KUR_EnforcePOPO_RejectsUnprotected(t *testing.T) {
	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(&models.EnrollmentOptionsLWCRFC9483{
			EnforcePOPO:    true,
			AcceptImplicit: true,
		}, nil)

	router, _ := newTestRouterWithStore(svc)
	kurDER := buildTestKUR(t, testIROptions{
		CN:                  "device-kur-popo-reject",
		WithImplicitConfirm: true,
	})

	resp := postCMP(t, router, "test-dms", kurDER)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, cmpBodyTagError, parseCMPResponseTag(t, resp.Body.Bytes()),
		"unprotected KUR must be rejected when EnforcePOPO=true")
	assert.Contains(t, parseCMPErrorReason(t, resp.Body.Bytes()), "proof of possession",
		"error must reference POPO/protection requirement")

	svc.AssertNotCalled(t, "LWCReenroll", mock.Anything, mock.Anything, mock.Anything)
}

// ---------------------------------------------------------------------------
// Cycle 19: KUR + EnforcePOPO=true + valid protection → accepted
// ---------------------------------------------------------------------------

// TestHandleCMP_KUR_EnforcePOPO_AcceptsProtected verifies the positive case
// of RFC 9483 §4.1.3: a KUR with valid message-level protection IS accepted
// as proof of possession of the old key, and LWCReenroll is called.
func TestHandleCMP_KUR_EnforcePOPO_AcceptsProtected(t *testing.T) {
	issuedCert, _ := buildSelfSignedCert(t, "device-kur-popo-ok")
	signerCert, signerKey := buildSelfSignedCert(t, "device-kur-signer")

	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(&models.EnrollmentOptionsLWCRFC9483{
			EnforcePOPO:    true,
			AcceptImplicit: true,
		}, nil)
	svc.On("LWCReenroll", mock.Anything, mock.AnythingOfType("*x509.CertificateRequest"), "test-dms").
		Return(issuedCert, nil)

	router, _ := newTestRouterWithStore(svc)
	kurDER := buildTestKUR(t, testIROptions{
		CN:                  "device-kur-popo-ok",
		WithImplicitConfirm: true,
	})
	signedKUR := signCMPMessage(t, kurDER, signerCert, signerKey)

	resp := postCMP(t, router, "test-dms", signedKUR)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, cmpBodyTagKUP, parseCMPResponseTag(t, resp.Body.Bytes()),
		"protected KUR must be accepted when EnforcePOPO=true")

	svc.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Cycle 20: KUR + EnforcePOPO=false + no protection → accepted
// ---------------------------------------------------------------------------

// TestHandleCMP_KUR_NoPOPO_NotEnforced verifies that when EnforcePOPO=false
// (default), an unprotected KUR is accepted. Transport-layer mTLS provides
// client authentication in this mode; message-level POPO is not required.
func TestHandleCMP_KUR_NoPOPO_NotEnforced(t *testing.T) {
	issuedCert, _ := buildSelfSignedCert(t, "device-kur-nopopo")

	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(&models.EnrollmentOptionsLWCRFC9483{
			EnforcePOPO:    false,
			AcceptImplicit: true,
		}, nil)
	svc.On("LWCReenroll", mock.Anything, mock.AnythingOfType("*x509.CertificateRequest"), "test-dms").
		Return(issuedCert, nil)

	router, _ := newTestRouterWithStore(svc)
	kurDER := buildTestKUR(t, testIROptions{
		CN:                  "device-kur-nopopo",
		WithImplicitConfirm: true,
	})

	resp := postCMP(t, router, "test-dms", kurDER)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, cmpBodyTagKUP, parseCMPResponseTag(t, resp.Body.Bytes()),
		"unprotected KUR must be accepted when EnforcePOPO=false")

	svc.AssertExpectations(t)
}

// buildCRLReasonExtension encodes an Extensions SEQUENCE containing id-ce-CRLReasons.
func buildCRLReasonExtension(t *testing.T, reason int) []byte {
	t.Helper()

	// The extnValue is an OCTET STRING wrapping an ENUMERATED.
	enumDER, err := asn1.Marshal(asn1.Enumerated(reason))
	require.NoError(t, err)
	extnValueDER, err := asn1.Marshal(enumDER) // OCTET STRING wrapping the DER
	require.NoError(t, err)

	oidCRLReason := asn1.ObjectIdentifier{2, 5, 29, 21}
	oidDER, err := asn1.Marshal(oidCRLReason)
	require.NoError(t, err)

	// Extension ::= SEQUENCE { extnID OID, extnValue OCTET STRING }
	extSeqDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      concatBytes(oidDER, extnValueDER),
	})
	require.NoError(t, err)

	// Extensions ::= SEQUENCE OF Extension
	extsDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      extSeqDER,
	})
	require.NoError(t, err)

	return extsDER
}

// ---------------------------------------------------------------------------
// Polling / lost-response recovery (RFC 4210 §5.3.22) tests
// ---------------------------------------------------------------------------

// TestHandleCMP_PollReq_WhileIssued_DeliversCert verifies that a pollReq
// against an ISSUED row delivers the cert in an ip/cp body. The row stays in
// the store afterwards so certConf can still operate.
func TestHandleCMP_PollReq_WhileIssued_DeliversCert(t *testing.T) {
	issuedCert, _ := buildSelfSignedCert(t, "recovery-device-001")

	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(&models.EnrollmentOptionsLWCRFC9483{}, nil)

	router, store := newTestRouterWithStore(svc)

	txID := make([]byte, 16)
	_, err := rand.Read(txID)
	require.NoError(t, err)
	require.NoError(t, store.Insert(context.Background(), storage.CMPTransaction{
		TransactionID: hex.EncodeToString(txID),
		DMSID:         "test-dms",
		State:         storage.CMPTransactionStateIssued,
		Certificate:   (*models.X509Certificate)(issuedCert),
		ExpiresAt:     time.Now().Add(5 * time.Minute),
		CreatedAt:     time.Now(),
	}))

	pollDER := buildTestPollReq(t, txID, 0)
	resp := postCMP(t, router, "test-dms", pollDER)

	require.Equal(t, http.StatusOK, resp.Code)
	tag := parseResponseBodyTag(t, resp.Body.Bytes())
	assert.Contains(t, []int{cmpBodyTagIP, cmpBodyTagCP}, tag,
		"ISSUED-state pollReq must deliver via ip or cp")
	status, hasCKP := parseIPBodyStatus(t, resp.Body.Bytes())
	assert.Equal(t, pkiStatusAccepted, status, "delivered cert response must be accepted (0)")
	assert.True(t, hasCKP, "delivered response must carry CertifiedKeyPair with the cert")

	// Row remains so certConf can verify against it.
	_, still := store.Peek(hex.EncodeToString(txID))
	assert.True(t, still, "pollReq delivery must not delete the row")
}

// TestHandleCMP_PollReq_UnknownTxID_ReturnsError verifies that a pollReq
// referring to no known transaction is rejected with an error PKIMessage
// rather than a stalled response or a 500.
func TestHandleCMP_PollReq_UnknownTxID_ReturnsError(t *testing.T) {
	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(&models.EnrollmentOptionsLWCRFC9483{}, nil)

	router, _ := newTestRouterWithStore(svc)

	unknownTxID := make([]byte, 16)
	_, err := rand.Read(unknownTxID)
	require.NoError(t, err)

	pollDER := buildTestPollReq(t, unknownTxID, 0)
	resp := postCMP(t, router, "test-dms", pollDER)

	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, cmpBodyTagError, parseResponseBodyTag(t, resp.Body.Bytes()),
		"unknown transactionID on pollReq must yield a CMP error body")
}

// TestHandleCMP_PollReq_IssueFailed_ReturnsErrorWithReason verifies that an
// ISSUE_FAILED row (kept for forward-compatibility with future async
// reintroduction) surfaces the failure reason in an error PKIMessage.
func TestHandleCMP_PollReq_IssueFailed_ReturnsErrorWithReason(t *testing.T) {
	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(&models.EnrollmentOptionsLWCRFC9483{}, nil)

	router, store := newTestRouterWithStore(svc)

	txID := make([]byte, 16)
	_, err := rand.Read(txID)
	require.NoError(t, err)
	require.NoError(t, store.Insert(context.Background(), storage.CMPTransaction{
		TransactionID: hex.EncodeToString(txID),
		DMSID:         "test-dms",
		State:         storage.CMPTransactionStateIssueFailed,
		ErrorMessage:  "CA returned: profile constraint violated",
		ExpiresAt:     time.Now().Add(5 * time.Minute),
		CreatedAt:     time.Now(),
	}))

	pollDER := buildTestPollReq(t, txID, 0)
	resp := postCMP(t, router, "test-dms", pollDER)

	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, cmpBodyTagError, parseResponseBodyTag(t, resp.Body.Bytes()),
		"ISSUE_FAILED state must produce a CMP error body, not pollRep")
}
