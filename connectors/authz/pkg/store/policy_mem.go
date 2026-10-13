package store

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/lamassuiot/lamassuiot/connectors/authz/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
)

// InMemoryPolicyStore is an in-memory PolicyStore intended for unit tests.
type InMemoryPolicyStore struct {
	mu       sync.RWMutex
	policies map[string]*models.Policy
}

func NewInMemoryPolicyStore() *InMemoryPolicyStore {
	return &InMemoryPolicyStore{policies: make(map[string]*models.Policy)}
}

func (s *InMemoryPolicyStore) Create(_ context.Context, policy *models.Policy) error {
	if policy.ID == "" {
		policy.ID = uuid.New().String()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.policies[policy.ID]; ok {
		return fmt.Errorf("policy with ID %s already exists", policy.ID)
	}
	cp := *policy
	s.policies[policy.ID] = &cp
	return nil
}

func (s *InMemoryPolicyStore) Exists(_ context.Context, id string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.policies[id]
	return ok, nil
}

func (s *InMemoryPolicyStore) Get(_ context.Context, id string) (*models.Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.policies[id]
	if !ok {
		return nil, fmt.Errorf("policy not found: %s", id)
	}
	cp := *p
	return &cp, nil
}

func (s *InMemoryPolicyStore) Update(_ context.Context, policy *models.Policy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.policies[policy.ID]; !ok {
		return fmt.Errorf("policy not found: %s", policy.ID)
	}
	cp := *policy
	s.policies[policy.ID] = &cp
	return nil
}

func (s *InMemoryPolicyStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.policies[id]; !ok {
		return fmt.Errorf("policy not found: %s", id)
	}
	delete(s.policies, id)
	return nil
}

func (s *InMemoryPolicyStore) List(_ context.Context, _ *resources.QueryParameters) ([]*models.Policy, string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*models.Policy, 0, len(s.policies))
	for _, p := range s.policies {
		cp := *p
		out = append(out, &cp)
	}
	return out, "", nil
}

func (s *InMemoryPolicyStore) Search(ctx context.Context, query string) ([]*models.Policy, error) {
	all, _, err := s.List(ctx, nil)
	if err != nil {
		return nil, err
	}
	if query == "" {
		return all, nil
	}
	lower := strings.ToLower(query)
	var matched []*models.Policy
	for _, p := range all {
		if strings.Contains(strings.ToLower(p.ID), lower) ||
			strings.Contains(strings.ToLower(p.Name), lower) ||
			strings.Contains(strings.ToLower(p.Description), lower) {
			matched = append(matched, p)
		}
	}
	return matched, nil
}
