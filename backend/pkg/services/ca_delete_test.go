package services

import (
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	coreservices "github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"
)

// deleteCARepo records the destructive steps of DeleteCA. children lists the child CAs of each CA, and deleting a CA
// in failDelete fails with its error.
type deleteCARepo struct {
	*importCARepo
	parentQueries int
	deleted       []string
	children      map[string][]string
	failDelete    map[string]error
}

func (repo *deleteCARepo) SelectByParentCA(_ context.Context, parentID string, req storage.StorageListRequest[models.CACertificate]) (string, error) {
	repo.parentQueries++
	for _, id := range repo.children[parentID] {
		if ca, ok := repo.cas[id]; ok {
			req.ApplyFunc(ca)
		}
	}
	return "", nil
}

func (repo *deleteCARepo) Delete(_ context.Context, id string) error {
	if err := repo.failDelete[id]; err != nil {
		return err
	}
	repo.deleted = append(repo.deleted, id)
	delete(repo.cas, id)
	return nil
}

// deleteCertRepo holds the key of each serial in held for the CRL settings of the CA it maps to. It records the key
// checks and releases.
type deleteCertRepo struct {
	*importCertificateRepo
	held     map[string]string
	checked  [][]string
	released [][]string
	byCA     int
	lookups  map[string]int
	issued   map[string][]string
}

func (repo *deleteCertRepo) SelectExistsBySerialNumber(ctx context.Context, serial string) (bool, *models.Certificate, error) {
	if repo.lookups == nil {
		repo.lookups = map[string]int{}
	}
	repo.lookups[serial]++
	return repo.importCertificateRepo.SelectExistsBySerialNumber(ctx, serial)
}

func (repo *deleteCertRepo) CRLSettingsHoldingKey(_ context.Context, serials []string) ([]string, error) {
	repo.checked = append(repo.checked, serials)
	holders := []string{}
	for _, serial := range serials {
		if caID, ok := repo.held[serial]; ok && !slices.Contains(holders, caID) {
			holders = append(holders, caID)
		}
	}
	slices.Sort(holders)
	return holders, nil
}

func (repo *deleteCertRepo) ReleaseKey(_ context.Context, serials []string) error {
	repo.released = append(repo.released, serials)
	return nil
}

func (repo *deleteCertRepo) SelectByCA(_ context.Context, caID string, req storage.StorageListRequest[models.Certificate]) (string, error) {
	repo.byCA++
	for _, serial := range repo.issued[caID] {
		req.ApplyFunc(repo.certificates[serial])
	}
	return "", nil
}

// cascadeRecorder records what a CA does, through svc.service, to its child CAs and the certificates it issued.
// Child CAs are revoked and deleted by the backend; certificates are only recorded.
type cascadeRecorder struct {
	*CAServiceBackend
	revokedCAs   []string
	revokedCerts []string
	deletedCerts []string
}

func (r *cascadeRecorder) UpdateCAStatus(ctx context.Context, input coreservices.UpdateCAStatusInput) (*models.CACertificate, error) {
	r.revokedCAs = append(r.revokedCAs, input.CAID)
	return r.CAServiceBackend.UpdateCAStatus(ctx, input)
}

func (r *cascadeRecorder) UpdateCertificateStatus(_ context.Context, input coreservices.UpdateCertificateStatusInput) (*models.Certificate, error) {
	r.revokedCerts = append(r.revokedCerts, input.SerialNumber)
	return &models.Certificate{}, nil
}

func (r *cascadeRecorder) DeleteCertificate(_ context.Context, input coreservices.DeleteCertificateInput) error {
	r.deletedCerts = append(r.deletedCerts, input.SerialNumber)
	return nil
}

// record routes the calls the service makes on itself through a cascadeRecorder.
func (f deleteCAFixture) record() *cascadeRecorder {
	r := &cascadeRecorder{CAServiceBackend: f.svc}
	f.svc.service = r
	return r
}

// addIssuedCertificate adds the certificate serial, issued by the CA caID.
func (f deleteCAFixture) addIssuedCertificate(caID, serial string) {
	f.certs.certificates[serial] = models.Certificate{SerialNumber: serial, Status: models.StatusActive,
		IssuerCAMetadata: models.IssuerCAMetadata{ID: caID}}
	if f.certs.issued == nil {
		f.certs.issued = map[string][]string{}
	}
	f.certs.issued[caID] = append(f.certs.issued[caID], serial)
}

// deleteCAKMS holds the key of the CA.
type deleteCAKMS struct{ *importCAKMS }

func (kms deleteCAKMS) GetKey(context.Context, coreservices.GetKeyInput) (*models.Key, error) {
	return &models.Key{KeyID: "k1", EngineID: "e1"}, nil
}

type deleteCAFixture struct {
	svc   *CAServiceBackend
	cas   *deleteCARepo
	certs *deleteCertRepo
	kms   *importCAKMS
}

// newDeleteCAFixture holds the CA "ca-1", revoked with reason, whose current certificate c2 reissued c1 on the same key.
func newDeleteCAFixture(t *testing.T, reason models.RevocationReason) deleteCAFixture {
	t.Helper()
	previous := caValidator
	caValidator = validator.New()
	t.Cleanup(func() { caValidator = previous })

	pub := importCAChain(t, false)[0]
	cert := func(serial string, metadata map[string]any) models.Certificate {
		return models.Certificate{SerialNumber: serial, Certificate: (*models.X509Certificate)(pub), Status: models.StatusRevoked,
			RevocationReason: reason, EngineID: "e1", KeyID: "k1", Metadata: metadata, Type: models.CertificateTypeManaged}
	}
	c1 := cert("c1", map[string]any{models.CAMetadataReissuedAsKey: "c2"})
	c2 := cert("c2", map[string]any{models.CAMetadataReissuedFromKey: "c1"})

	cas := &deleteCARepo{importCARepo: &importCARepo{cas: map[string]models.CACertificate{
		"ca-1": {ID: "ca-1", Certificate: c2, CertificateSerialNumber: "c2"},
	}}}
	certs := &deleteCertRepo{importCertificateRepo: &importCertificateRepo{certificates: map[string]models.Certificate{"c1": c1, "c2": c2}}}
	kms := &importCAKMS{importedKey: &models.Key{KeyID: "k1", EngineID: "e1"}}
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	svc := &CAServiceBackend{caStorage: cas, certStorage: certs, kmsService: deleteCAKMS{kms}, logger: logrus.NewEntry(logger)}
	svc.service = svc
	return deleteCAFixture{svc: svc, cas: cas, certs: certs, kms: kms}
}

// addChildCA adds the CA id, issued by parent, whose only certificate has the serial id-cert.
func (f deleteCAFixture) addChildCA(t *testing.T, parent, id string, status models.CertificateStatus) {
	t.Helper()
	pub := importCAChain(t, false)[0]
	cert := models.Certificate{SerialNumber: id + "-cert", Certificate: (*models.X509Certificate)(pub), Status: status,
		RevocationReason: models.RevocationReason(ocsp.CessationOfOperation), EngineID: "e1", KeyID: "k-" + id,
		Metadata: map[string]any{}, Type: models.CertificateTypeManaged}
	f.cas.cas[id] = models.CACertificate{ID: id, Certificate: cert, CertificateSerialNumber: cert.SerialNumber}
	f.certs.certificates[cert.SerialNumber] = cert
	if f.cas.children == nil {
		f.cas.children = map[string][]string{}
	}
	f.cas.children[parent] = append(f.cas.children[parent], id)
}

// While the final CRL of the CA is pending, DeleteCA fails before any visible change (§9).
func TestDeleteCAFinalCRLPendingChangesNothing(t *testing.T) {
	f := newDeleteCAFixture(t, models.RevocationReason(ocsp.KeyCompromise))
	f.certs.held = map[string]string{"c2": "ca-1"}

	err := f.svc.DeleteCA(context.Background(), coreservices.DeleteCAInput{CAID: "ca-1"})
	require.ErrorIs(t, err, errs.ErrCAFinalCRLPending)
	require.Contains(t, err.Error(), "ca-1")
	require.Contains(t, err.Error(), "retry")
	require.Contains(t, err.Error(), "CRL monitor job", "a lost event leaves the final CRL to the monitor job")

	require.Zero(t, f.cas.parentQueries, "no child CA is revoked")
	require.Zero(t, f.certs.byCA, "no certificate is revoked")
	require.Empty(t, f.cas.deleted)
	require.Empty(t, f.certs.released)
	require.Empty(t, f.kms.deletedKeys)
}

// A CA on hold never reaches FINAL: the message says to revoke it permanently.
func TestDeleteCAOnHoldAsksForPermanentRevocation(t *testing.T) {
	f := newDeleteCAFixture(t, models.RevocationReason(ocsp.CertificateHold))
	f.certs.held = map[string]string{"c2": "ca-1"}

	err := f.svc.DeleteCA(context.Background(), coreservices.DeleteCAInput{CAID: "ca-1"})
	require.ErrorIs(t, err, errs.ErrCAFinalCRLPending)
	require.Contains(t, err.Error(), "revoke it permanently")
	require.Empty(t, f.cas.deleted)
}

// The key of the CA signs the CRLs of another CA: waiting does not help, so the error names that CA.
func TestDeleteCAKeyHeldByAnotherCA(t *testing.T) {
	f := newDeleteCAFixture(t, models.RevocationReason(ocsp.KeyCompromise))
	f.certs.held = map[string]string{"c1": "ca-other"}

	err := f.svc.DeleteCA(context.Background(), coreservices.DeleteCAInput{CAID: "ca-1"})
	require.ErrorIs(t, err, errs.ErrCAKeyHeldByCRLSettings)
	require.Contains(t, err.Error(), "ca-other")
	require.NotContains(t, err.Error(), "retry")
	require.Empty(t, f.cas.deleted)
	require.Empty(t, f.kms.deletedKeys)
}

// When both the CA and another CA hold the key, the other CA is reported: only it needs an action.
func TestDeleteCAKeyHeldByItselfAndAnotherCA(t *testing.T) {
	f := newDeleteCAFixture(t, models.RevocationReason(ocsp.KeyCompromise))
	f.certs.held = map[string]string{"c2": "ca-1", "c1": "ca-other"}

	err := f.svc.DeleteCA(context.Background(), coreservices.DeleteCAInput{CAID: "ca-1"})
	require.ErrorIs(t, err, errs.ErrCAKeyHeldByCRLSettings)
	require.Contains(t, err.Error(), "ca-other")
}

// The check covers every certificate DeleteCA would release: the current one and the ones it reissued.
func TestDeleteCAChecksTheKeyOfItsWholeHistory(t *testing.T) {
	f := newDeleteCAFixture(t, models.RevocationReason(ocsp.KeyCompromise))

	require.NoError(t, f.svc.DeleteCA(context.Background(), coreservices.DeleteCAInput{CAID: "ca-1"}))
	require.Equal(t, [][]string{{"c2", "c1"}}, f.certs.checked)
	require.Equal(t, [][]string{{"c2", "c1"}}, f.certs.released)
	require.Equal(t, []string{"ca-1"}, f.cas.deleted)
	require.Len(t, f.kms.deletedKeys, 1)
}

// DeleteCA walks the reissue history of the CA once: the key check and the key release use the same certificates.
func TestDeleteCAWalksTheHistoryOnce(t *testing.T) {
	f := newDeleteCAFixture(t, models.RevocationReason(ocsp.KeyCompromise))

	require.NoError(t, f.svc.DeleteCA(context.Background(), coreservices.DeleteCAInput{CAID: "ca-1"}))
	require.Equal(t, 1, f.certs.lookups["c1"], "the reissued certificate is looked up once")
	require.Equal(t, f.certs.checked, f.certs.released)
}

// A cascade delete checks every descendant before any change: one whose final CRL is pending stops the whole
// delete, and the error names it.
func TestCascadeDeleteChecksEveryDescendantBeforeAnyChange(t *testing.T) {
	f := newDeleteCAFixture(t, models.RevocationReason(ocsp.KeyCompromise))
	f.svc.allowCascadeDelete = true
	f.addChildCA(t, "ca-1", "ca-2", models.StatusRevoked)
	f.addChildCA(t, "ca-2", "ca-3", models.StatusRevoked)
	f.certs.held = map[string]string{"ca-3-cert": "ca-3"}

	err := f.svc.DeleteCA(context.Background(), coreservices.DeleteCAInput{CAID: "ca-1", CascadeDelete: true})
	require.ErrorIs(t, err, errs.ErrCAFinalCRLPending)
	require.Contains(t, err.Error(), "ca-3")

	require.Empty(t, f.cas.deleted)
	require.Zero(t, f.certs.byCA, "no issued certificate is deleted")
	require.Empty(t, f.certs.released)
	require.Empty(t, f.kms.deletedKeys)
}

// A cascade delete does not start while a descendant cannot be deleted, such as an active one.
func TestCascadeDeleteRejectsAnActiveDescendant(t *testing.T) {
	f := newDeleteCAFixture(t, models.RevocationReason(ocsp.KeyCompromise))
	f.svc.allowCascadeDelete = true
	f.addChildCA(t, "ca-1", "ca-2", models.StatusRevoked)
	f.addChildCA(t, "ca-2", "ca-3", models.StatusActive)

	err := f.svc.DeleteCA(context.Background(), coreservices.DeleteCAInput{CAID: "ca-1", CascadeDelete: true})
	require.ErrorIs(t, err, errs.ErrCAStatus)
	require.Contains(t, err.Error(), "ca-3")
	require.Contains(t, err.Error(), string(models.StatusActive))
	require.Empty(t, f.cas.deleted)
	require.Zero(t, f.certs.byCA)
}

// If deleting a child CA fails anyway, its parent stays: no CA is left behind an issuer that no longer exists.
func TestCascadeDeleteKeepsTheParentWhenAChildFails(t *testing.T) {
	f := newDeleteCAFixture(t, models.RevocationReason(ocsp.KeyCompromise))
	f.svc.allowCascadeDelete = true
	f.addChildCA(t, "ca-1", "ca-2", models.StatusRevoked)
	f.cas.failDelete = map[string]error{"ca-2": errors.New("storage down")}

	err := f.svc.DeleteCA(context.Background(), coreservices.DeleteCAInput{CAID: "ca-1", CascadeDelete: true})
	require.Error(t, err)
	require.Contains(t, err.Error(), "ca-2")
	require.NotContains(t, f.cas.deleted, "ca-1")
	require.Contains(t, f.cas.cas, "ca-1")
	require.Empty(t, f.kms.deletedKeys)
}

func TestCascadeDeleteChildConflictRetainsErrorPrefixAndChild(t *testing.T) {
	for _, conflict := range []error{errs.ErrCAFinalCRLPending, errs.ErrCAKeyHeldByCRLSettings} {
		t.Run(conflict.Error(), func(t *testing.T) {
			f := newDeleteCAFixture(t, models.RevocationReason(ocsp.KeyCompromise))
			f.svc.allowCascadeDelete = true
			f.addChildCA(t, "ca-1", "ca-2", models.StatusRevoked)
			f.addChildCA(t, "ca-2", "ca-3", models.StatusRevoked)
			f.cas.failDelete = map[string]error{"ca-3": conflict}

			err := f.svc.DeleteCA(context.Background(), coreservices.DeleteCAInput{CAID: "ca-1", CascadeDelete: true})
			require.ErrorIs(t, err, conflict)
			require.True(t, strings.HasPrefix(err.Error(), conflict.Error()+": "), "SDK must recognize the error: %s", err)
			require.Contains(t, err.Error(), "ca-2")
			require.Contains(t, err.Error(), "ca-3")
			require.NotContains(t, f.cas.deleted, "ca-1")
		})
	}
}

// A cascade delete of a CA whose descendants are all ready deletes them, children before their parent.
func TestCascadeDeleteDeletesTheDescendantsFirst(t *testing.T) {
	f := newDeleteCAFixture(t, models.RevocationReason(ocsp.KeyCompromise))
	f.svc.allowCascadeDelete = true
	f.addChildCA(t, "ca-1", "ca-2", models.StatusRevoked)
	f.addChildCA(t, "ca-2", "ca-3", models.StatusRevoked)

	require.NoError(t, f.svc.DeleteCA(context.Background(), coreservices.DeleteCAInput{CAID: "ca-1", CascadeDelete: true}))
	require.Equal(t, []string{"ca-3", "ca-2", "ca-1"}, f.cas.deleted)
}

// A cascade delete also deletes the certificates each CA issued, the descendants' first.
func TestCascadeDeleteDeletesTheIssuedCertificates(t *testing.T) {
	f := newDeleteCAFixture(t, models.RevocationReason(ocsp.KeyCompromise))
	f.svc.allowCascadeDelete = true
	f.addChildCA(t, "ca-1", "ca-2", models.StatusRevoked)
	f.addIssuedCertificate("ca-1", "leaf-1")
	f.addIssuedCertificate("ca-2", "leaf-2")
	r := f.record()

	require.NoError(t, f.svc.DeleteCA(context.Background(), coreservices.DeleteCAInput{CAID: "ca-1", CascadeDelete: true}))
	require.Equal(t, []string{"leaf-2", "leaf-1"}, r.deletedCerts)
	require.Empty(t, r.revokedCerts)
	require.Empty(t, r.revokedCAs)
}

// Without cascade, deleting a CA revokes its child CAs and the certificates it issued instead of deleting them.
func TestDeleteCAWithoutCascadeRevokesWhatItIssued(t *testing.T) {
	f := newDeleteCAFixture(t, models.RevocationReason(ocsp.KeyCompromise))
	f.addChildCA(t, "ca-1", "ca-2", models.StatusActive)
	f.addIssuedCertificate("ca-1", "leaf-1")
	r := f.record()

	require.NoError(t, f.svc.DeleteCA(context.Background(), coreservices.DeleteCAInput{CAID: "ca-1"}))
	require.Equal(t, []string{"ca-2"}, r.revokedCAs)
	require.Equal(t, []string{"leaf-1"}, r.revokedCerts)
	require.Equal(t, []string{"ca-1"}, f.cas.deleted)
	require.Empty(t, r.deletedCerts)
}

// Revoking a CA revokes its child CAs, with cessationOfOperation, and the certificates it issued.
func TestRevokingACARevokesWhatItIssued(t *testing.T) {
	f := newDeleteCAFixture(t, models.RevocationReason(ocsp.CertificateHold))
	f.addChildCA(t, "ca-1", "ca-2", models.StatusActive)
	f.addIssuedCertificate("ca-1", "leaf-1")
	f.addIssuedCertificate("ca-2", "leaf-2")
	r := f.record()

	_, err := f.svc.UpdateCAStatus(context.Background(), coreservices.UpdateCAStatusInput{
		CAID: "ca-1", Status: models.StatusRevoked, RevocationReason: models.RevocationReason(ocsp.KeyCompromise)})
	require.NoError(t, err)
	require.Equal(t, []string{"ca-2"}, r.revokedCAs)
	require.Equal(t, []string{"leaf-2", "leaf-1"}, r.revokedCerts)
	child := f.certs.certificates["ca-2-cert"]
	require.Equal(t, models.StatusRevoked, child.Status)
	require.Equal(t, models.RevocationReason(ocsp.CessationOfOperation), child.RevocationReason)
}
