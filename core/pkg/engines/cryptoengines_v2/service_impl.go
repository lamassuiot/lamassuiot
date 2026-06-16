package cryptoenginesv2

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type service struct {
	registry Registry
	meta     MetadataStore
	backends BackendRegistry
	clock    func() time.Time
	idgen    func() KeyID
}

func NewService(r Registry, m MetadataStore, b BackendRegistry) Service {
	return &service{
		registry: r, meta: m, backends: b,
		clock: time.Now,
		idgen: func() KeyID { return KeyID(uuid.NewString()) },
	}
}

func (s *service) CreateKey(ctx context.Context, spec CreateKeySpec) (KeyHandle, error) {
	algSpec, err := s.registry.Get(spec.Algorithm)
	if err != nil {
		return nil, err
	}

	if err := validateOpsAgainstAlgorithm(algSpec, spec.Operations); err != nil {
		return nil, err
	}

	backend, err := s.backends.Select(spec)
	if err != nil {
		return nil, err
	}

	spec.KeyID = s.idgen()

	handle, err := backend.Generate(ctx, spec)
	if err != nil {
		return nil, err
	}

	rec := KeyRecord{
		Metadata: KeyMetadata{
			KeyID:       spec.KeyID,
			Algorithm:   spec.Algorithm,
			Operations:  spec.Operations,
			State:       StateEnabled,
			PublicKey:   handle.Metadata().PublicKey,
			CreatedAt:   s.clock(),
			NotBefore:   spec.NotBefore,
			NotAfter:    spec.NotAfter,
			Origin:      OriginGenerated,
			Tags:        spec.Tags,
			PolicyID: spec.PolicyID,
		},
		BackendRef: BackendRef{Backend: backend.Name(), URI: handle.BackendURI()},
	}

	if err := s.meta.Put(ctx, rec); err != nil {
		_ = backend.Destroy(ctx, rec.BackendRef)
		return nil, err
	}

	return handle, nil
}

func (s *service) GetKey(ctx context.Context, id KeyID) (KeyHandle, error) {
	rec, err := s.meta.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if rec.Metadata.State == StateDestroyed {
		return nil, fmt.Errorf("key %s is destroyed", id)
	}

	backend, err := s.backends.Lookup(rec.BackendRef.Backend)
	if err != nil {
		return nil, err
	}

	return backend.Load(ctx, rec)
}

// ... ImportKey, ListKeys, UpdateKey, Enable/Disable, Schedule/Cancel
//     Deletion, BackupKey, RestoreKey, aliases, GenerateRandom — same shape:
//     validate → check policy → call backend → persist metadata → audit.

func (s *service) ImportKey(ctx context.Context, spec ImportKeySpec) (KeyHandle, error) {
	return nil, fmt.Errorf("TBImplemented")
}

func (s *service) ListKeys(ctx context.Context, opts ListOpts) (ListKeysResult, error) {
	return ListKeysResult{}, fmt.Errorf("TBImplemented")
}

func (s *service) UpdateKey(ctx context.Context, id KeyID, patch KeyPatch) (KeyMetadata, error) {
	return KeyMetadata{}, fmt.Errorf("TBImplemented")
}

func (s *service) EnableKey(ctx context.Context, id KeyID) error {
	return fmt.Errorf("TBImplemented")
}

func (s *service) DisableKey(ctx context.Context, id KeyID) error {
	return fmt.Errorf("TBImplemented")
}

func (s *service) ScheduleDeletion(ctx context.Context, id KeyID, after time.Duration) error {
	return fmt.Errorf("TBImplemented")
}

func (s *service) CancelDeletion(ctx context.Context, id KeyID) error {
	return fmt.Errorf("TBImplemented")
}

func (s *service) BackupKey(ctx context.Context, id KeyID) (BackupBlob, error) {
	return BackupBlob{}, fmt.Errorf("TBImplemented")
}

func (s *service) RestoreKey(ctx context.Context, blob BackupBlob) (KeyHandle, error) {
	return nil, fmt.Errorf("TBImplemented")
}

func (s *service) CreateAlias(ctx context.Context, alias string, target KeyID) error {
	return fmt.Errorf("TBImplemented")
}

func (s *service) DeleteAlias(ctx context.Context, alias string) error {
	return fmt.Errorf("TBImplemented")
}

func (s *service) ResolveAlias(ctx context.Context, alias string) (KeyID, error) {
	return "", fmt.Errorf("TBImplemented")
}

func (s *service) GenerateRandom(ctx context.Context, n int) ([]byte, error) {
	return nil, fmt.Errorf("TBImplemented")
}
