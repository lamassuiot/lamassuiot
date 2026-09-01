// Package memory provides an in-memory implementation of
// cryptoenginesv2.MetadataStore for tests and local development.
//
// The store is safe for concurrent use. It deep-copies records on Put and
// Get to prevent external mutation from racing with internal state.
// Paginated listing is stable: keys are sorted by KeyID ascending, and
// PageToken is the last KeyID returned in the prior page.
//
// This store ignores ListOpts.Filter — use a real store (Postgres) if
// you need filtering.
package memory

import (
	"context"
	"fmt"
	"sort"
	"sync"

	cryptoenginesv2 "github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines_v2"
)

type (
	KeyID          = cryptoenginesv2.KeyID
	KeyMetadata    = cryptoenginesv2.KeyMetadata
	KeyRecord      = cryptoenginesv2.KeyRecord
	KeyState       = cryptoenginesv2.KeyState
	ListKeysResult = cryptoenginesv2.ListKeysResult
	ListOpts       = cryptoenginesv2.ListOpts
	Operation      = cryptoenginesv2.Operation
)

// Store is an in-memory MetadataStore. The zero value is NOT ready; use
// New() to construct one.
type Store struct {
	mu      sync.RWMutex
	records map[KeyID]KeyRecord
	aliases map[string]KeyID
}

// New returns an empty in-memory store.
func New() *Store {
	return &Store{
		records: make(map[KeyID]KeyRecord),
		aliases: make(map[string]KeyID),
	}
}

// ---------------------------------------------------------------------------
// CRUD on records
// ---------------------------------------------------------------------------

func (s *Store) Put(_ context.Context, rec KeyRecord) error {
	if rec.Metadata.KeyID == "" {
		return fmt.Errorf("memory: KeyRecord.Metadata.KeyID is empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[rec.Metadata.KeyID] = cloneRecord(rec)
	return nil
}

func (s *Store) Get(_ context.Context, id KeyID) (KeyRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.records[id]
	if !ok {
		return KeyRecord{}, fmt.Errorf("%w: %s", cryptoenginesv2.ErrKeyNotFound, id)
	}
	return cloneRecord(rec), nil
}

func (s *Store) List(_ context.Context, opts ListOpts) (ListKeysResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ids := make([]KeyID, 0, len(s.records))
	for id := range s.records {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

	// Skip ids <= PageToken if a token was provided.
	start := 0
	if opts.PageToken != "" {
		start = sort.Search(len(ids), func(i int) bool {
			return string(ids[i]) > opts.PageToken
		})
	}

	size := opts.PageSize
	if size <= 0 {
		size = 50 // default page size
	}

	end := start + size
	if end > len(ids) {
		end = len(ids)
	}

	out := ListKeysResult{
		Keys: make([]KeyMetadata, 0, end-start),
	}
	for _, id := range ids[start:end] {
		out.Keys = append(out.Keys, cloneMetadata(s.records[id].Metadata))
	}

	// Set NextPageToken only if more results remain.
	if end < len(ids) {
		out.NextPageToken = string(ids[end-1])
	}
	return out, nil
}

func (s *Store) Delete(_ context.Context, id KeyID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.records[id]; !ok {
		return fmt.Errorf("%w: %s", cryptoenginesv2.ErrKeyNotFound, id)
	}
	delete(s.records, id)

	// Aliases that pointed to this key are now dangling — remove them.
	for alias, target := range s.aliases {
		if target == id {
			delete(s.aliases, alias)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// State transitions (atomic CAS)
// ---------------------------------------------------------------------------

func (s *Store) UpdateState(_ context.Context, id KeyID, from, to KeyState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.records[id]
	if !ok {
		return fmt.Errorf("%w: %s", cryptoenginesv2.ErrKeyNotFound, id)
	}
	if rec.Metadata.State != from {
		return fmt.Errorf("%w: key %s is in state %q, expected %q",
			cryptoenginesv2.ErrInvalidStateTransition, id, rec.Metadata.State, from)
	}
	rec.Metadata.State = to
	s.records[id] = rec
	return nil
}

// ---------------------------------------------------------------------------
// Aliases
// ---------------------------------------------------------------------------

func (s *Store) PutAlias(_ context.Context, alias string, target KeyID) error {
	if alias == "" {
		return fmt.Errorf("memory: alias is empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	// Aliases must point to existing keys.
	if _, ok := s.records[target]; !ok {
		return fmt.Errorf("%w: alias target %s", cryptoenginesv2.ErrKeyNotFound, target)
	}
	s.aliases[alias] = target
	return nil
}

func (s *Store) GetAlias(_ context.Context, alias string) (KeyID, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.aliases[alias]
	if !ok {
		return "", fmt.Errorf("%w: alias %q", cryptoenginesv2.ErrAliasNotFound, alias)
	}
	return id, nil
}

func (s *Store) DeleteAlias(_ context.Context, alias string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.aliases[alias]; !ok {
		return fmt.Errorf("%w: alias %q", cryptoenginesv2.ErrAliasNotFound, alias)
	}
	delete(s.aliases, alias)
	return nil
}

// ---------------------------------------------------------------------------
// Deep-copy helpers
// ---------------------------------------------------------------------------

func cloneRecord(rec KeyRecord) KeyRecord {
	return KeyRecord{
		Metadata:   cloneMetadata(rec.Metadata),
		BackendRef: rec.BackendRef, // value type, safe to copy
	}
}

func cloneMetadata(m KeyMetadata) KeyMetadata {
	out := m // shallow copy of value fields
	// Operations slice
	if m.Operations != nil {
		out.Operations = make([]Operation, len(m.Operations))
		copy(out.Operations, m.Operations)
	}
	// Tags map
	if m.Tags != nil {
		out.Tags = make(map[string]string, len(m.Tags))
		for k, v := range m.Tags {
			out.Tags[k] = v
		}
	}
	// Time pointers — share the underlying time.Time (immutable), but copy
	// the pointer so the caller can repoint without affecting the store.
	if m.NotBefore != nil {
		nb := *m.NotBefore
		out.NotBefore = &nb
	}
	if m.NotAfter != nil {
		na := *m.NotAfter
		out.NotAfter = &na
	}
	// PublicKey is crypto.PublicKey (interface). Its concrete types are
	// considered immutable in practice (*rsa.PublicKey, *ecdsa.PublicKey,
	// etc. — fields are unexported or read-only after construction).
	// Deep-copying them would be expensive and provides no real safety.
	return out
}
