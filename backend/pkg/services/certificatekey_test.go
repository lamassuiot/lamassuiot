package services

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	coreservices "github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/engines/crypto/software/v3"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"gocloud.dev/blob/memblob"
)

// KMS fixture requiring the full URI for signing, even if a bare ID can locate
// the key. This catches losing the engine between lookup and SignMessage.
type certificateKeyKMS struct {
	coreservices.KMSService
	privateKey                    *ecdsa.PrivateKey
	key                           models.Key
	importEngine                  string
	lookups, signatures, bindings []string
	unavailable                   bool
	lookupErr, listErr            error
	candidates                    []models.Key
	listCalls                     int
	lookupOverride                func(string) (*models.Key, error)
}

func newCertificateKeyKMS(t *testing.T) *certificateKeyKMS {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	id, err := software.NewSoftwareCryptoEngine(logrus.NewEntry(logrus.New())).EncodePKIXPublicKeyDigest(context.Background(), &key.PublicKey)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	return &certificateKeyKMS{privateKey: key, key: models.Key{
		KeyID: id, EngineID: "filesystem-test-1", PKCS11URI: buildPKCS11ID("filesystem-test-1", id, "private"),
		Algorithm: "ECDSA", Size: 256, HasPrivateKey: true,
		PublicKey: base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
	}}
}

func (kms *certificateKeyKMS) ImportKey(_ context.Context, input coreservices.ImportKeyInput) (*models.Key, error) {
	kms.importEngine = input.EngineID
	return &kms.key, nil
}

func (kms *certificateKeyKMS) CreateKey(context.Context, coreservices.CreateKeyInput) (*models.Key, error) {
	return &kms.key, nil
}

func (kms *certificateKeyKMS) GetKey(_ context.Context, input coreservices.GetKeyInput) (*models.Key, error) {
	kms.lookups = append(kms.lookups, input.Identifier)
	if kms.lookupErr != nil {
		return nil, kms.lookupErr
	}
	if kms.lookupOverride != nil {
		return kms.lookupOverride(input.Identifier)
	}
	if kms.unavailable {
		return nil, errs.ErrKeyNotFound
	}
	if input.Identifier != kms.key.PKCS11URI && input.Identifier != kms.key.KeyID {
		return nil, errs.ErrKeyNotFound
	}
	return &kms.key, nil
}

func (kms *certificateKeyKMS) GetKeys(_ context.Context, input coreservices.GetKeysInput) (string, error) {
	kms.listCalls++
	if kms.listErr != nil {
		return "", kms.listErr
	}
	if kms.unavailable {
		return "", nil
	}
	candidates := kms.candidates
	if candidates == nil {
		candidates = []models.Key{kms.key}
	}
	for _, key := range candidates {
		match := true
		for _, filter := range input.QueryParameters.Filters {
			switch filter.Field {
			case "public_key":
				match = match && key.PublicKey == filter.Value
			case "engine_id":
				match = match && key.EngineID == filter.Value
			default:
				return "", fmt.Errorf("unexpected filter: %s", filter.Field)
			}
		}
		if match {
			input.ApplyFunc(key)
		}
	}
	return "", nil
}

func (kms *certificateKeyKMS) UpdateKeyMetadata(_ context.Context, input coreservices.UpdateKeyMetadataInput) (*models.Key, error) {
	kms.bindings = append(kms.bindings, input.ID)
	if input.ID != kms.key.PKCS11URI {
		return nil, fmt.Errorf("metadata update lost key URI: %s", input.ID)
	}
	return &kms.key, nil
}

func (kms *certificateKeyKMS) SignMessage(_ context.Context, input coreservices.SignMessageInput) (*models.MessageSignature, error) {
	kms.signatures = append(kms.signatures, input.Identifier)
	if input.Identifier != kms.key.PKCS11URI {
		return nil, fmt.Errorf("signing lost key URI: %s", input.Identifier)
	}
	signature, err := kms.privateKey.Sign(rand.Reader, input.Message, crypto.SHA256)
	return &models.MessageSignature{Signature: signature}, err
}

type certificateKeyCARepo struct {
	storage.CACertificatesRepo
	ca *models.CACertificate
}

func (repo *certificateKeyCARepo) Insert(_ context.Context, ca *models.CACertificate) (*models.CACertificate, error) {
	repo.ca = ca
	return ca, nil
}

func (repo *certificateKeyCARepo) Update(ctx context.Context, ca *models.CACertificate) (*models.CACertificate, error) {
	return repo.Insert(ctx, ca)
}

func (repo *certificateKeyCARepo) SelectExistsByID(_ context.Context, id string) (bool, *models.CACertificate, error) {
	return repo.ca != nil && repo.ca.ID == id, repo.ca, nil
}

func (repo *certificateKeyCARepo) SelectAll(_ context.Context, req storage.StorageListRequest[models.CACertificate]) (string, error) {
	if repo.ca != nil {
		req.ApplyFunc(*repo.ca)
	}
	return "", nil
}

func (*certificateKeyCARepo) SelectByIssuerAndAuthorityKeyID(context.Context, models.Subject, string, storage.StorageListRequest[models.CACertificate]) (string, error) {
	return "", nil
}

type certificateKeyCertRepo struct{ storage.CertificatesRepo }

func (*certificateKeyCertRepo) Insert(_ context.Context, cert *models.Certificate) (*models.Certificate, error) {
	return cert, nil
}
func (*certificateKeyCertRepo) Update(_ context.Context, cert *models.Certificate) (*models.Certificate, error) {
	return cert, nil
}
func (*certificateKeyCertRepo) SelectByCAIDAndStatus(context.Context, string, models.CertificateStatus, storage.StorageListRequest[models.Certificate]) (string, error) {
	return "", nil
}

type certificateKeyProfileRepo struct{ storage.IssuanceProfileRepo }

func (*certificateKeyProfileRepo) SelectByID(context.Context, string) (bool, *models.IssuanceProfile, error) {
	return true, &models.IssuanceProfile{}, nil
}

type certificateKeyVARepo struct {
	storage.VARepo
	role *models.VARole
}

func (repo *certificateKeyVARepo) Insert(_ context.Context, role *models.VARole) (*models.VARole, error) {
	repo.role = role
	return role, nil
}
func (repo *certificateKeyVARepo) Update(ctx context.Context, role *models.VARole) (*models.VARole, error) {
	return repo.Insert(ctx, role)
}
func (repo *certificateKeyVARepo) Get(_ context.Context, ski string) (bool, *models.VARole, error) {
	return repo.role != nil && repo.role.CASubjectKeyID == ski, repo.role, nil
}

func certificateKeyTestCAService(t *testing.T, kms *certificateKeyKMS) (coreservices.CAService, *certificateKeyCARepo, *logrus.Entry) {
	t.Helper()
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	entry := logrus.NewEntry(logger)
	repo := &certificateKeyCARepo{}
	svc, err := NewCAService(CAServiceBuilder{Logger: entry, CAStorage: repo, KMSService: kms,
		CertificateStorage: &certificateKeyCertRepo{}, IssuanceProfileStorage: &certificateKeyProfileRepo{}})
	require.NoError(t, err)
	return svc, repo, entry
}

func certificateKeyTestCertificate(t *testing.T, kms *certificateKeyKMS, ski []byte) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "external-root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		SubjectKeyId: ski, AuthorityKeyId: ski, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &kms.privateKey.PublicKey, kms.privateKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func TestImportCAResolvesDifferentSKIAndGeneratesCRL(t *testing.T) {
	kms := newCertificateKeyKMS(t)
	svc, repo, logger := certificateKeyTestCAService(t, kms)
	cert := certificateKeyTestCertificate(t, kms, bytes.Repeat([]byte{0x42}, 20))
	require.NotEqual(t, kms.key.KeyID, hex.EncodeToString(cert.SubjectKeyId))
	ca, err := svc.ImportCA(context.Background(), coreservices.ImportCAInput{
		ID: "imported-ca", CACertificate: (*models.X509Certificate)(cert), Key: kms.privateKey, EngineID: kms.key.EngineID,
	})
	require.NoError(t, err)
	require.Equal(t, kms.key.EngineID, repo.ca.Certificate.EngineID)
	require.Equal(t, hex.EncodeToString(cert.SubjectKeyId), ca.Certificate.SubjectKeyID)
	require.Equal(t, kms.key.EngineID, kms.importEngine)
	require.Equal(t, []string{kms.key.PKCS11URI}, kms.bindings)

	bucket := memblob.OpenBucket(nil)
	t.Cleanup(func() { require.NoError(t, bucket.Close()) })
	crlSvc, err := NewCRLService(CRLServiceBuilder{Logger: logger, CAClient: svc, KMSClient: kms,
		VARepo: &certificateKeyVARepo{}, Bucket: bucket})
	require.NoError(t, err)
	_, err = crlSvc.InitCRLRole(context.Background(), ca.Certificate.SubjectKeyID)
	require.NoError(t, err)
	crl, err := crlSvc.GetCRL(context.Background(), coreservices.GetCRLInput{
		CASubjectKeyID: ca.Certificate.SubjectKeyID, CRLVersion: big.NewInt(0),
	})
	require.NoError(t, err)
	require.NoError(t, crl.CheckSignatureFrom(cert))
	require.Equal(t, []string{buildPKCS11ID(kms.key.EngineID, ca.Certificate.SubjectKeyID, "private"), kms.key.PKCS11URI}, kms.lookups)
	require.Equal(t, []string{kms.key.PKCS11URI}, kms.signatures)
}

func TestCreateAndReissueCAResolveCertificateKey(t *testing.T) {
	kms := newCertificateKeyKMS(t)
	svc, repo, _ := certificateKeyTestCAService(t, kms)
	ca, err := svc.CreateCA(context.Background(), coreservices.CreateCAInput{
		ID: "created-ca", ProfileID: "profile", Subject: models.Subject{CommonName: "root"},
		KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.ECDSA), Bits: 256},
		CAExpiration: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour)}, EngineID: kms.key.EngineID,
	})
	require.NoError(t, err)
	require.Equal(t, kms.key.EngineID, ca.Certificate.EngineID)
	reissued, err := svc.ReissueCA(context.Background(), coreservices.ReissueCAInput{CAID: ca.ID})
	require.NoError(t, err)
	require.Equal(t, kms.key.EngineID, reissued.Certificate.EngineID)
	require.Equal(t, kms.key.EngineID, repo.ca.Certificate.EngineID)
	require.NoError(t, (*x509.Certificate)(reissued.Certificate.Certificate).CheckSignatureFrom((*x509.Certificate)(ca.Certificate.Certificate)))
}

func TestGetCertificateKey(t *testing.T) {
	for _, tc := range []struct {
		name, engine                    string
		externalSKI, arbitraryID, noSKI bool
	}{
		{name: "SKI in engine", engine: "filesystem-test-1"},
		{name: "SKI without engine"},
		{name: "external SKI uses digest", engine: "filesystem-test-1", externalSKI: true},
		{name: "missing SKI uses digest", engine: "filesystem-test-1", noSKI: true},
		{name: "provider ID uses public key", engine: "filesystem-test-1", externalSKI: true, arbitraryID: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kms := newCertificateKeyKMS(t)
			ski, err := hex.DecodeString(kms.key.KeyID)
			require.NoError(t, err)
			if tc.externalSKI {
				ski = []byte{1, 2, 3}
			}
			cert := certificateKeyTestCertificate(t, kms, ski)
			if tc.noSKI {
				cert.SubjectKeyId = nil
			}
			if tc.arbitraryID {
				kms.key.KeyID = "provider-assigned-id"
				kms.key.PKCS11URI = buildPKCS11ID(kms.key.EngineID, kms.key.KeyID, "private")
			}
			resolved, err := (&CAServiceBackend{kmsService: kms}).GetCertificateKey(context.Background(), coreservices.GetCertificateKeyInput{Certificate: (*models.X509Certificate)(cert), EngineID: tc.engine})
			require.NoError(t, err)
			require.Equal(t, kms.key.KeyID, resolved.KeyID)
			if tc.arbitraryID {
				require.Equal(t, 1, kms.listCalls)
			} else {
				require.Zero(t, kms.listCalls)
			}
			require.Empty(t, kms.bindings)
			if tc.noSKI {
				return // x509.CreateRevocationList requires an issuer SKI.
			}
			signer := NewCertificateSigner(context.Background(), &models.Certificate{Certificate: (*models.X509Certificate)(cert), EngineID: tc.engine}, &CAServiceBackend{kmsService: kms}, kms)
			der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: time.Now(), NextUpdate: time.Now().Add(time.Hour)}, cert, signer)
			require.NoError(t, err)
			crl, err := x509.ParseRevocationList(der)
			require.NoError(t, err)
			require.NoError(t, crl.CheckSignatureFrom(cert))
			require.Equal(t, []string{kms.key.PKCS11URI}, kms.signatures)
		})
	}
}

func TestGetCertificateKeyRejectsInvalidCandidates(t *testing.T) {
	for _, name := range []string{"wrong public key", "malformed public key", "public key only", "wrong engine", "ambiguous engines", "ambiguous keys"} {
		t.Run(name, func(t *testing.T) {
			kms := newCertificateKeyKMS(t)
			cert := certificateKeyTestCertificate(t, kms, []byte{1})
			engine := kms.key.EngineID
			expected := errs.ErrKeyNotFound
			switch name {
			case "wrong public key":
				cert = certificateKeyTestCertificate(t, newCertificateKeyKMS(t), []byte{1})
				expected = errs.ErrCAValidCertAndPrivKey
			case "malformed public key":
				kms.key.PublicKey = "invalid"
				expected = errs.ErrCAValidCertAndPrivKey
			case "public key only":
				kms.key.HasPrivateKey = false
			case "wrong engine":
				engine = "another-engine"
				kms.lookupOverride = func(string) (*models.Key, error) { return &kms.key, nil }
			case "ambiguous engines", "ambiguous keys":
				engine = ""
				duplicate := kms.key
				if name == "ambiguous engines" {
					duplicate.EngineID = "another-engine"
				} else {
					engine = kms.key.EngineID
					duplicate.KeyID = "duplicate-id"
				}
				kms.candidates = []models.Key{kms.key, duplicate}
				kms.lookupOverride = func(string) (*models.Key, error) { return nil, errs.ErrKeyEngineRequired }
				expected = errs.ErrKeyEngineRequired
			}
			if name == "wrong public key" || name == "malformed public key" {
				kms.lookupOverride = func(string) (*models.Key, error) { return &kms.key, nil }
			}
			resolved, err := (&CAServiceBackend{kmsService: kms}).GetCertificateKey(context.Background(), coreservices.GetCertificateKeyInput{Certificate: (*models.X509Certificate)(cert), EngineID: engine})
			require.Nil(t, resolved)
			if name == "ambiguous keys" {
				require.ErrorContains(t, err, "multiple private keys")
			} else {
				require.ErrorIs(t, err, expected)
			}
			require.Empty(t, kms.signatures)
		})
	}
}

func TestGetCertificateKeySkipsWrongSKICandidate(t *testing.T) {
	kms := newCertificateKeyKMS(t)
	wrong := newCertificateKeyKMS(t)
	cert := certificateKeyTestCertificate(t, kms, []byte{1})
	kms.lookupOverride = func(identifier string) (*models.Key, error) {
		if identifier == buildPKCS11ID(kms.key.EngineID, "01", "private") {
			return &wrong.key, nil
		}
		return &kms.key, nil
	}
	resolved, err := (&CAServiceBackend{kmsService: kms}).GetCertificateKey(context.Background(), coreservices.GetCertificateKeyInput{Certificate: (*models.X509Certificate)(cert), EngineID: kms.key.EngineID})
	require.NoError(t, err)
	require.Equal(t, kms.key.KeyID, resolved.KeyID)
	require.Len(t, kms.lookups, 2)
}

func TestGetCertificateKeyPropagatesKMSErrors(t *testing.T) {
	for _, stage := range []string{"lookup", "list"} {
		t.Run(stage, func(t *testing.T) {
			kms := newCertificateKeyKMS(t)
			cert := certificateKeyTestCertificate(t, kms, []byte{1})
			expected := errors.New("KMS unavailable")
			if stage == "lookup" {
				kms.lookupErr = expected
			} else {
				kms.lookupErr = errs.ErrKeyNotFound
				kms.listErr = expected
			}
			_, err := (&CAServiceBackend{kmsService: kms}).GetCertificateKey(context.Background(), coreservices.GetCertificateKeyInput{Certificate: (*models.X509Certificate)(cert)})
			require.ErrorIs(t, err, expected)
			if stage == "lookup" {
				require.Len(t, kms.lookups, 1)
				require.Zero(t, kms.listCalls)
			}
		})
	}
	kms := newCertificateKeyKMS(t)
	_, err := (&CAServiceBackend{kmsService: kms}).GetCertificateKey(context.Background(), coreservices.GetCertificateKeyInput{})
	require.ErrorIs(t, err, errs.ErrValidateBadRequest)
}

func TestImportCARejectsMismatchedKey(t *testing.T) {
	kms := newCertificateKeyKMS(t)
	cert := certificateKeyTestCertificate(t, newCertificateKeyKMS(t), []byte{1})
	svc, repo, _ := certificateKeyTestCAService(t, kms)
	_, err := svc.ImportCA(context.Background(), coreservices.ImportCAInput{ID: "mismatched-ca", CACertificate: (*models.X509Certificate)(cert), Key: kms.privateKey})
	require.ErrorIs(t, err, errs.ErrCAValidCertAndPrivKey)
	require.Nil(t, repo.ca)
	require.Empty(t, kms.bindings)
}

func TestImportCAFindsExistingKey(t *testing.T) {
	for _, known := range []bool{false, true} {
		t.Run(fmt.Sprintf("existing=%t", known), func(t *testing.T) {
			kms := newCertificateKeyKMS(t)
			cert := certificateKeyTestCertificate(t, kms, []byte{1})
			kms.unavailable = !known
			svc, _, _ := certificateKeyTestCAService(t, kms)
			ca, err := svc.ImportCA(context.Background(), coreservices.ImportCAInput{ID: "imported-ca", CACertificate: (*models.X509Certificate)(cert), EngineID: kms.key.EngineID})
			require.NoError(t, err)
			if known {
				require.Equal(t, models.CertificateTypeManaged, ca.Certificate.Type)
				require.Equal(t, kms.key.EngineID, ca.Certificate.EngineID)
				require.Equal(t, []string{kms.key.PKCS11URI}, kms.bindings)
			} else {
				require.Equal(t, models.CertificateTypeImportedWithoutKey, ca.Certificate.Type)
				require.Empty(t, kms.bindings)
			}
		})
	}
}
