package services

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	coreservices "github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// Only the repository operations used by ImportCA are implemented. In particular,
// child discovery matches both issuer subject and stored AKI, as the SQL store does.
type importCARepo struct {
	storage.CACertificatesRepo
	mu           sync.Mutex
	cas          map[string]models.CACertificate
	lookupErr    error
	insertErr    error
	insertCalls  int
	childQueries int
}

func (repo *importCARepo) WithIDLock(ctx context.Context, _ string, fn func(storage.CACertificatesRepo) error) error {
	repo.mu.Lock()
	defer repo.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	return fn(repo)
}

func (repo *importCARepo) Insert(_ context.Context, ca *models.CACertificate) (*models.CACertificate, error) {
	repo.insertCalls++
	if repo.insertErr != nil {
		return nil, repo.insertErr
	}
	repo.cas[ca.ID] = *ca
	return ca, nil
}

func (repo *importCARepo) Update(ctx context.Context, ca *models.CACertificate) (*models.CACertificate, error) {
	repo.cas[ca.ID] = *ca
	return ca, nil
}

func (repo *importCARepo) SelectExistsByID(_ context.Context, id string) (bool, *models.CACertificate, error) {
	if repo.lookupErr != nil {
		return false, nil, repo.lookupErr
	}
	ca, exists := repo.cas[id]
	if !exists {
		return false, nil, nil
	}
	return true, &ca, nil
}

func (repo *importCARepo) SelectAll(_ context.Context, req storage.StorageListRequest[models.CACertificate]) (string, error) {
	for _, ca := range repo.cas {
		req.ApplyFunc(ca)
	}
	return "", nil
}

func (repo *importCARepo) SelectBySubjectAndSubjectKeyID(ctx context.Context, subject models.Subject, ski string, req storage.StorageListRequest[models.CACertificate]) (string, error) {
	return repo.SelectAll(ctx, storage.StorageListRequest[models.CACertificate]{ApplyFunc: func(ca models.CACertificate) {
		if reflect.DeepEqual(ca.Certificate.Subject, subject) && ca.Certificate.SubjectKeyID == ski {
			req.ApplyFunc(ca)
		}
	}})
}

func (repo *importCARepo) SelectByIssuerAndAuthorityKeyID(ctx context.Context, issuer models.Subject, aki string, req storage.StorageListRequest[models.CACertificate]) (string, error) {
	repo.childQueries++
	return repo.SelectAll(ctx, storage.StorageListRequest[models.CACertificate]{ApplyFunc: func(ca models.CACertificate) {
		if reflect.DeepEqual(ca.Certificate.Issuer, issuer) && ca.Certificate.AuthorityKeyID == aki {
			req.ApplyFunc(ca)
		}
	}})
}

type importCAKMS struct {
	coreservices.KMSService
	getKeyCalls    int
	importKeyCalls int
}

func (kms *importCAKMS) GetKey(context.Context, coreservices.GetKeyInput) (*models.Key, error) {
	kms.getKeyCalls++
	return nil, errs.ErrKeyNotFound
}

func (kms *importCAKMS) ImportKey(context.Context, coreservices.ImportKeyInput) (*models.Key, error) {
	kms.importKeyCalls++
	return nil, errors.New("unexpected key import")
}

func newImportCAService(t *testing.T) (*CAServiceBackend, *importCARepo) {
	t.Helper()
	repo := &importCARepo{cas: make(map[string]models.CACertificate)}
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	return &CAServiceBackend{caStorage: repo, kmsService: &importCAKMS{}, logger: logrus.NewEntry(logger)}, repo
}

func importCAChain(t *testing.T, omitChildAKI bool) []*x509.Certificate {
	t.Helper()
	var certs []*x509.Certificate
	var parentKey *ecdsa.PrivateKey
	for level := range 3 {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		template := &x509.Certificate{
			SerialNumber:          big.NewInt(int64(level + 1)),
			Subject:               pkix.Name{CommonName: []string{"root", "intermediate", "child"}[level]},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(time.Hour),
			BasicConstraintsValid: true,
			IsCA:                  true,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			SubjectKeyId:          []byte{byte(level + 1)},
		}
		parent := template
		signer := key
		if level == 0 {
			template.AuthorityKeyId = template.SubjectKeyId
		} else {
			parent = certs[level-1]
			signer = parentKey
			if level == 2 && omitChildAKI {
				// Create a valid certificate without AKI to exercise issuer-subject
				// fallback. Go derives AKI from the signing parent's SKI otherwise.
				parentCopy := *parent
				parentCopy.SubjectKeyId = nil
				parent = &parentCopy
			}
		}
		der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, signer)
		require.NoError(t, err)
		cert, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		certs = append(certs, cert)
		parentKey = key
	}
	return certs
}

func TestImportCAPreservesAuthorityKeyID(t *testing.T) {
	for _, tc := range []struct {
		name         string
		omitChildAKI bool
	}{
		{name: "parent found by AKI"},
		{name: "parent found by issuer subject", omitChildAKI: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, repo := newImportCAService(t)
			chain := importCAChain(t, tc.omitChildAKI)
			var imported []*models.CACertificate
			for _, cert := range chain {
				ca, err := svc.ImportCA(context.Background(), coreservices.ImportCAInput{
					ID: cert.Subject.CommonName, CACertificate: (*models.X509Certificate)(cert),
				})
				require.NoError(t, err)
				require.Equal(t, hex.EncodeToString(cert.AuthorityKeyId), ca.Certificate.AuthorityKeyID)
				require.Equal(t, ca.Certificate.AuthorityKeyID, repo.cas[ca.ID].Certificate.AuthorityKeyID)
				imported = append(imported, ca)
			}
			child := imported[2]
			require.Equal(t, 2, child.Level)
			require.Equal(t, models.IssuerCAMetadata{ID: imported[1].ID, SN: imported[1].Certificate.SerialNumber, Level: 1}, child.Certificate.IssuerCAMetadata)
			if !tc.omitChildAKI {
				// VA regeneration uses this value as the issuing CA's SKI.
				require.Equal(t, imported[1].Certificate.SubjectKeyID, child.Certificate.AuthorityKeyID)
				require.NotEqual(t, imported[0].Certificate.SubjectKeyID, child.Certificate.AuthorityKeyID)
			}
		})
	}
}

func TestImportCAReparentsDescendants(t *testing.T) {
	svc, repo := newImportCAService(t)
	chain := importCAChain(t, false)
	// The intermediate initially has no known parent. Import its child while
	// the intermediate exists, then import the root to reconnect the subtree.
	for _, index := range []int{1, 2, 0} {
		cert := chain[index]
		_, err := svc.ImportCA(context.Background(), coreservices.ImportCAInput{
			ID: cert.Subject.CommonName, CACertificate: (*models.X509Certificate)(cert),
		})
		require.NoError(t, err)
	}
	for level, cert := range chain {
		ca := repo.cas[cert.Subject.CommonName]
		require.Equal(t, level, ca.Level, "level of %s", ca.ID)
		require.Equal(t, hex.EncodeToString(cert.AuthorityKeyId), ca.Certificate.AuthorityKeyID)
		if level > 0 {
			parent := repo.cas[chain[level-1].Subject.CommonName]
			require.Equal(t, models.IssuerCAMetadata{ID: parent.ID, SN: parent.Certificate.SerialNumber, Level: parent.Level}, ca.Certificate.IssuerCAMetadata)
		}
	}
}

func TestImportCARejectsDuplicateID(t *testing.T) {
	for _, withKey := range []bool{false, true} {
		name := "without key"
		if withKey {
			name = "with key"
		}
		t.Run(name, func(t *testing.T) {
			svc, repo := newImportCAService(t)
			chain := importCAChain(t, false)
			original, err := svc.ImportCA(context.Background(), coreservices.ImportCAInput{
				ID: "existing-ca", CACertificate: (*models.X509Certificate)(chain[0]),
			})
			require.NoError(t, err)
			input := coreservices.ImportCAInput{
				ID: original.ID, CACertificate: (*models.X509Certificate)(chain[1]),
			}
			if withKey {
				input.Key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
			}
			kms := svc.kmsService.(*importCAKMS)
			keyReads := kms.getKeyCalls
			duplicate, err := svc.ImportCA(context.Background(), input)
			require.ErrorIs(t, err, errs.ErrCAAlreadyExists)
			require.Nil(t, duplicate)
			require.Equal(t, 1, repo.insertCalls)
			require.Len(t, repo.cas, 1)
			require.Equal(t, *original, repo.cas[original.ID])
			require.Equal(t, keyReads, kms.getKeyCalls, "duplicate rejection must precede KMS calls")
			require.Zero(t, kms.importKeyCalls)
		})
	}
}

func TestImportCAPropagatesIDLookupError(t *testing.T) {
	svc, repo := newImportCAService(t)
	repo.lookupErr = errors.New("CA storage unavailable")
	ca, err := svc.ImportCA(context.Background(), coreservices.ImportCAInput{
		ID: "new-ca", CACertificate: (*models.X509Certificate)(importCAChain(t, false)[0]),
	})
	require.ErrorIs(t, err, repo.lookupErr)
	require.Nil(t, ca)
	require.Zero(t, repo.insertCalls)
	require.Zero(t, svc.kmsService.(*importCAKMS).getKeyCalls)
}

func TestImportCAGeneratesUniqueIDs(t *testing.T) {
	svc, repo := newImportCAService(t)
	chain := importCAChain(t, false)
	var ids []string
	for _, cert := range chain[:2] {
		ca, err := svc.ImportCA(context.Background(), coreservices.ImportCAInput{
			CACertificate: (*models.X509Certificate)(cert),
		})
		require.NoError(t, err)
		require.NotEmpty(t, ca.ID)
		ids = append(ids, ca.ID)
	}
	require.NotEqual(t, ids[0], ids[1])
	require.Len(t, repo.cas, 2)
}

func TestImportCAStopsOnInsertFailureAndAllowsRetry(t *testing.T) {
	svc, repo := newImportCAService(t)
	repo.insertErr = errors.New("insert failed")
	input := coreservices.ImportCAInput{
		ID: "retry-ca", CACertificate: (*models.X509Certificate)(importCAChain(t, false)[0]),
	}
	ca, err := svc.ImportCA(context.Background(), input)
	require.ErrorIs(t, err, repo.insertErr)
	require.Nil(t, ca)
	require.Empty(t, repo.cas)
	require.Zero(t, repo.childQueries, "a failed insert must not trigger reparenting")
	repo.insertErr = nil
	ca, err = svc.ImportCA(context.Background(), input)
	require.NoError(t, err)
	require.Equal(t, input.ID, ca.ID)
}
