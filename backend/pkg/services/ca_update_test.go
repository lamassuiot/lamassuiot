package services

import (
	"context"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	coreservices "github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"
)

// updateCARepo is an in-memory CA repository whose WithIDLock mimics the
// PostgreSQL one: per-ID, non-reentrant, context-aware. The repository handed
// to the callback is a distinct view, so the tests can tell whether the
// service read/wrote through the lock-owning repository or went around it.
type updateCARepo struct {
	storage.CACertificatesRepo

	dataMu sync.Mutex
	cas    map[string]models.CACertificate

	locksMu sync.Mutex
	locks   map[string]chan struct{}
	lockErr error

	// readDelay widens the read-modify-write window so that missing
	// serialization shows up reliably.
	readDelay time.Duration

	lockCalls         atomic.Int32
	lockedIDs         sync.Map
	locked            atomic.Int32
	unscopedAccesses  atomic.Int32
	updates           atomic.Int32
	lockHeldOnParents atomic.Bool
}

func (repo *updateCARepo) lockFor(id string) chan struct{} {
	repo.locksMu.Lock()
	defer repo.locksMu.Unlock()
	if repo.locks == nil {
		repo.locks = map[string]chan struct{}{}
	}
	if _, ok := repo.locks[id]; !ok {
		repo.locks[id] = make(chan struct{}, 1)
	}
	return repo.locks[id]
}

func (repo *updateCARepo) WithIDLock(ctx context.Context, id string, fn func(storage.CACertificatesRepo) error) error {
	repo.lockCalls.Add(1)
	repo.lockedIDs.Store(id, true)
	if repo.lockErr != nil {
		return repo.lockErr
	}
	sem := repo.lockFor(id)
	select {
	case sem <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-sem }()
	repo.locked.Add(1)
	defer repo.locked.Add(-1)
	return fn(&updateCAScopedRepo{repo})
}

func (repo *updateCARepo) read(id string) (bool, *models.CACertificate, error) {
	repo.dataMu.Lock()
	ca, ok := repo.cas[id]
	repo.dataMu.Unlock()
	time.Sleep(repo.readDelay)
	if !ok {
		return false, nil, nil
	}
	return true, &ca, nil
}

func (repo *updateCARepo) write(ca *models.CACertificate) (*models.CACertificate, error) {
	repo.updates.Add(1)
	repo.dataMu.Lock()
	defer repo.dataMu.Unlock()
	repo.cas[ca.ID] = *ca
	return ca, nil
}

func (repo *updateCARepo) parents(parentID string, req storage.StorageListRequest[models.CACertificate]) (string, error) {
	if repo.locked.Load() > 0 {
		repo.lockHeldOnParents.Store(true)
	}
	repo.dataMu.Lock()
	var children []models.CACertificate
	for _, ca := range repo.cas {
		if ca.Certificate.IssuerCAMetadata.ID == parentID && ca.ID != parentID {
			children = append(children, ca)
		}
	}
	repo.dataMu.Unlock()
	for _, child := range children {
		req.ApplyFunc(child)
	}
	return "", nil
}

// Unscoped access: whatever the service does through svc.caStorage directly.
func (repo *updateCARepo) SelectExistsByID(_ context.Context, id string) (bool, *models.CACertificate, error) {
	repo.unscopedAccesses.Add(1)
	return repo.read(id)
}

func (repo *updateCARepo) Update(_ context.Context, ca *models.CACertificate) (*models.CACertificate, error) {
	repo.unscopedAccesses.Add(1)
	return repo.write(ca)
}

func (repo *updateCARepo) SelectByParentCA(_ context.Context, parentID string, req storage.StorageListRequest[models.CACertificate]) (string, error) {
	return repo.parents(parentID, req)
}

// Scoped access: the repository handed to the WithIDLock callback.
type updateCAScopedRepo struct{ *updateCARepo }

func (repo *updateCAScopedRepo) SelectExistsByID(_ context.Context, id string) (bool, *models.CACertificate, error) {
	return repo.read(id)
}

func (repo *updateCAScopedRepo) Update(_ context.Context, ca *models.CACertificate) (*models.CACertificate, error) {
	return repo.write(ca)
}

type updateCertRepo struct{ storage.CertificatesRepo }

func (updateCertRepo) SelectByCA(context.Context, string, storage.StorageListRequest[models.Certificate]) (string, error) {
	return "", nil
}

type knownProfileService struct{ coreservices.CAService }

func (knownProfileService) GetIssuanceProfileByID(_ context.Context, in coreservices.GetIssuanceProfileByIDInput) (*models.IssuanceProfile, error) {
	return &models.IssuanceProfile{ID: in.ProfileID}, nil
}

// cascadingService routes the service's self-calls (child CA revocation) back
// through the backend, as the real wiring does, and resolves profiles.
type cascadingService struct {
	coreservices.CAService
	svc *CAServiceBackend
}

func (s cascadingService) UpdateCAStatus(ctx context.Context, in coreservices.UpdateCAStatusInput) (*models.CACertificate, error) {
	return s.svc.UpdateCAStatus(ctx, in)
}

func (s cascadingService) GetIssuanceProfileByID(ctx context.Context, in coreservices.GetIssuanceProfileByIDInput) (*models.IssuanceProfile, error) {
	return knownProfileService{}.GetIssuanceProfileByID(ctx, in)
}

func newUpdateCAService(t *testing.T, cas ...models.CACertificate) (*CAServiceBackend, *updateCARepo) {
	t.Helper()
	if caValidator == nil {
		caValidator = validator.New()
	}
	repo := &updateCARepo{cas: map[string]models.CACertificate{}}
	for _, ca := range cas {
		repo.cas[ca.ID] = ca
	}
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	svc := &CAServiceBackend{
		caStorage:   repo,
		certStorage: updateCertRepo{},
		logger:      logrus.NewEntry(logger),
	}
	svc.service = cascadingService{svc: svc}
	return svc, repo
}

func activeCA(id string) models.CACertificate {
	return models.CACertificate{
		ID:       id,
		Metadata: map[string]any{},
		Certificate: models.Certificate{
			SerialNumber: "sn-" + id,
			Status:       models.StatusActive,
		},
	}
}

func testCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func addPatch(key string, value any) []models.PatchOperation {
	return []models.PatchOperation{{Op: models.PatchAdd, Path: "/" + key, Value: value}}
}

func requireLockedOnly(t *testing.T, repo *updateCARepo, id string) {
	t.Helper()
	require.EqualValues(t, 1, repo.lockCalls.Load(), "update must take the ID lock exactly once")
	_, ok := repo.lockedIDs.Load(id)
	require.True(t, ok, "lock must be taken on the CA being updated")
	require.Zero(t, repo.unscopedAccesses.Load(), "reads/writes must go through the lock-owning repository")
}

func TestUpdateCAMetadataUsesIDLock(t *testing.T) {
	svc, repo := newUpdateCAService(t, activeCA("ca1"))

	ca, err := svc.UpdateCAMetadata(testCtx(t), coreservices.UpdateCAMetadataInput{CAID: "ca1", Patches: addPatch("owner", "pki")})
	require.NoError(t, err)
	require.Equal(t, "pki", ca.Metadata["owner"])
	require.Equal(t, "pki", repo.cas["ca1"].Metadata["owner"])
	requireLockedOnly(t, repo, "ca1")
}

func TestUpdateCAProfileUsesIDLock(t *testing.T) {
	svc, repo := newUpdateCAService(t, activeCA("ca1"))

	ca, err := svc.UpdateCAProfile(testCtx(t), coreservices.UpdateCAProfileInput{CAID: "ca1", ProfileID: "p1"})
	require.NoError(t, err)
	require.Equal(t, "p1", ca.ProfileID)
	require.Equal(t, "p1", repo.cas["ca1"].ProfileID)
	requireLockedOnly(t, repo, "ca1")
}

func TestUpdateCAStatusUsesIDLock(t *testing.T) {
	held := activeCA("ca1")
	held.Certificate.Status = models.StatusRevoked
	held.Certificate.RevocationReason = ocsp.CertificateHold
	svc, repo := newUpdateCAService(t, held)

	ca, err := svc.UpdateCAStatus(testCtx(t), coreservices.UpdateCAStatusInput{CAID: "ca1", Status: models.StatusActive})
	require.NoError(t, err)
	require.Equal(t, models.StatusActive, ca.Certificate.Status)
	requireLockedOnly(t, repo, "ca1")
}

func TestUpdateCAMissingCAStillReportsNotFound(t *testing.T) {
	svc, repo := newUpdateCAService(t)
	ctx := testCtx(t)

	_, err := svc.UpdateCAMetadata(ctx, coreservices.UpdateCAMetadataInput{CAID: "nope", Patches: addPatch("k", "v")})
	require.ErrorIs(t, err, errs.ErrCANotFound)
	_, err = svc.UpdateCAProfile(ctx, coreservices.UpdateCAProfileInput{CAID: "nope", ProfileID: "p1"})
	require.ErrorIs(t, err, errs.ErrCANotFound)
	_, err = svc.UpdateCAStatus(ctx, coreservices.UpdateCAStatusInput{CAID: "nope", Status: models.StatusRevoked})
	require.ErrorIs(t, err, errs.ErrCANotFound)
	require.Zero(t, repo.updates.Load())
}

func TestUpdateCAFailsWithoutWritingWhenLockFails(t *testing.T) {
	svc, repo := newUpdateCAService(t, activeCA("ca1"))
	repo.lockErr = fmt.Errorf("lock unavailable")
	ctx := testCtx(t)

	_, err := svc.UpdateCAMetadata(ctx, coreservices.UpdateCAMetadataInput{CAID: "ca1", Patches: addPatch("k", "v")})
	require.ErrorContains(t, err, "lock unavailable")
	_, err = svc.UpdateCAProfile(ctx, coreservices.UpdateCAProfileInput{CAID: "ca1", ProfileID: "p1"})
	require.ErrorContains(t, err, "lock unavailable")
	_, err = svc.UpdateCAStatus(ctx, coreservices.UpdateCAStatusInput{CAID: "ca1", Status: models.StatusRevoked, RevocationReason: ocsp.KeyCompromise})
	require.ErrorContains(t, err, "lock unavailable")

	require.Zero(t, repo.updates.Load())
	require.Empty(t, repo.cas["ca1"].Metadata)
}

func TestUpdateCAHonoursCancelledContextWhileWaitingForLock(t *testing.T) {
	svc, repo := newUpdateCAService(t, activeCA("ca1"))
	sem := repo.lockFor("ca1")
	sem <- struct{}{} // another instance owns the lock
	defer func() { <-sem }()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := svc.UpdateCAMetadata(ctx, coreservices.UpdateCAMetadataInput{CAID: "ca1", Patches: addPatch("k", "v")})
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Zero(t, repo.updates.Load())
}

// Concurrent read-modify-write updates must not overwrite each other.
func TestConcurrentUpdateCAMetadataKeepsEveryPatch(t *testing.T) {
	svc, repo := newUpdateCAService(t, activeCA("ca1"))
	repo.readDelay = 5 * time.Millisecond
	ctx := testCtx(t)

	const n = 8
	var wg sync.WaitGroup
	errc := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := svc.UpdateCAMetadata(ctx, coreservices.UpdateCAMetadataInput{CAID: "ca1", Patches: addPatch(fmt.Sprintf("k%d", i), i)})
			errc <- err
		}(i)
	}
	wg.Wait()
	close(errc)
	for err := range errc {
		require.NoError(t, err)
	}
	require.Len(t, repo.cas["ca1"].Metadata, n, "a concurrent update was lost: %v", repo.cas["ca1"].Metadata)
}

// Different update operations on the same CA touch different columns of the
// same row; both must survive.
func TestConcurrentMetadataAndProfileUpdatesDoNotClobberEachOther(t *testing.T) {
	svc, repo := newUpdateCAService(t, activeCA("ca1"))
	repo.readDelay = 20 * time.Millisecond
	ctx := testCtx(t)

	var wg sync.WaitGroup
	var metaErr, profileErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, metaErr = svc.UpdateCAMetadata(ctx, coreservices.UpdateCAMetadataInput{CAID: "ca1", Patches: addPatch("owner", "pki")})
	}()
	go func() {
		defer wg.Done()
		_, profileErr = svc.UpdateCAProfile(ctx, coreservices.UpdateCAProfileInput{CAID: "ca1", ProfileID: "p1"})
	}()
	wg.Wait()
	require.NoError(t, metaErr)
	require.NoError(t, profileErr)

	got := repo.cas["ca1"]
	require.Equal(t, "pki", got.Metadata["owner"], "metadata update lost")
	require.Equal(t, "p1", got.ProfileID, "profile update lost")
}

// The status transition rules are validated against the state read under the
// lock: of two concurrent revocations, the second must see the first.
func TestConcurrentRevocationsAreSerialized(t *testing.T) {
	svc, repo := newUpdateCAService(t, activeCA("ca1"))
	repo.readDelay = 20 * time.Millisecond
	ctx := testCtx(t)

	reasons := []models.RevocationReason{ocsp.KeyCompromise, ocsp.Superseded}
	errc := make(chan error, len(reasons))
	var wg sync.WaitGroup
	for _, reason := range reasons {
		wg.Add(1)
		go func(reason models.RevocationReason) {
			defer wg.Done()
			_, err := svc.UpdateCAStatus(ctx, coreservices.UpdateCAStatusInput{CAID: "ca1", Status: models.StatusRevoked, RevocationReason: reason})
			errc <- err
		}(reason)
	}
	wg.Wait()
	close(errc)

	var failures []error
	for err := range errc {
		if err != nil {
			failures = append(failures, err)
		}
	}
	require.Len(t, failures, 1, "exactly one revocation may win")
	require.ErrorIs(t, failures[0], errs.ErrCertificateStatusTransitionNotAllowed)
}

// Revoking a CA cascades to its children. The cascade re-enters UpdateCAStatus
// (taking each child's own lock) and must run after the parent's lock is
// released, not inside it.
func TestUpdateCAStatusRevokeCascadesOutsideLock(t *testing.T) {
	parent := activeCA("parent")
	child := activeCA("child")
	child.Certificate.IssuerCAMetadata = models.IssuerCAMetadata{ID: "parent"}
	svc, repo := newUpdateCAService(t, parent, child)

	ca, err := svc.UpdateCAStatus(testCtx(t), coreservices.UpdateCAStatusInput{
		CAID: "parent", Status: models.StatusRevoked, RevocationReason: ocsp.KeyCompromise,
	})
	require.NoError(t, err)
	require.Equal(t, models.StatusRevoked, ca.Certificate.Status)

	require.Equal(t, models.StatusRevoked, repo.cas["parent"].Certificate.Status)
	require.Equal(t, models.StatusRevoked, repo.cas["child"].Certificate.Status, "child CA must be revoked by the cascade")
	require.False(t, repo.lockHeldOnParents.Load(), "the cascade must not run while the parent's lock is held")
	for _, id := range []string{"parent", "child"} {
		_, ok := repo.lockedIDs.Load(id)
		require.True(t, ok, "%s must be updated under its own lock", id)
	}
}
