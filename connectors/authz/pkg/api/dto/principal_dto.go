package dto

import (
	"time"

	"github.com/lamassuiot/authz/pkg/models"
)

// CreatePrincipalRequest for creating a new principal
type CreatePrincipalRequest struct {
	ID          string             `json:"id"`
	Name        string             `json:"name" binding:"required,min=1,max=255"`
	Description *string            `json:"description,omitempty" binding:"omitempty,max=1024"`
	Type        string             `json:"type"`
	AuthConfig  *models.AuthConfig `json:"authConfig"`
	Active      *bool              `json:"active"` // pointer to allow explicit false
}

// UpdatePrincipalRequest for updating a principal
type UpdatePrincipalRequest struct {
	Name        *string            `json:"name,omitempty"`
	Description *string            `json:"description,omitempty" binding:"omitempty,max=1024"`
	Enabled     *bool              `json:"enabled,omitempty"`
	AuthConfig  *models.AuthConfig `json:"authConfig,omitempty"`
	Active      *bool              `json:"active,omitempty"`
}

// PrincipalResponse represents a principal
type PrincipalResponse struct {
	ID          string             `json:"id"`
	Name        string             `json:"name"`
	Description string             `json:"description,omitempty"`
	Type        string             `json:"type"`
	Enabled     bool               `json:"enabled"`
	AuthConfig  *models.AuthConfig `json:"authConfig"`
	Active      bool               `json:"active"`
	CreatedAt   time.Time          `json:"createdAt"`
	UpdatedAt   time.Time          `json:"updatedAt"`
}

// ListPrincipalsResponse with pagination
type ListPrincipalsResponse struct {
	Principals []PrincipalResponse `json:"principals"`
	Pagination *PaginationResponse `json:"pagination,omitempty"`
}

// GrantPolicyRequest for assigning a policy to a principal
type GrantPolicyRequest struct {
	PolicyID  string `json:"policyId" binding:"required"`
	GrantedBy string `json:"grantedBy"`
}

// GrantPoliciesRequest for bulk assignment
type GrantPoliciesRequest struct {
	PolicyIDs []string `json:"policyIds" binding:"required,min=1"`
	GrantedBy string   `json:"grantedBy"`
}

// PrincipalPolicyResponse shows policy assignments
type PrincipalPolicyResponse struct {
	PrincipalID string    `json:"principalId"`
	PolicyID    string    `json:"policyId"`
	PolicyName  string    `json:"policyName"`
	GrantedAt   time.Time `json:"grantedAt"`
	GrantedBy   string    `json:"grantedBy,omitempty"`
}

// ListPrincipalPoliciesResponse returns policy assignments
type ListPrincipalPoliciesResponse struct {
	PrincipalID string                    `json:"principalId"`
	Policies    []PrincipalPolicyResponse `json:"policies"`
}
