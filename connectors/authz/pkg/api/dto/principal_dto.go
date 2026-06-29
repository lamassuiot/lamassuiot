package dto

import (
	"time"

	"github.com/lamassuiot/lamassuiot/connectors/authz/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
)

// CreatePrincipalRequest for creating a new principal
type CreatePrincipalRequest struct {
	ID          string             `json:"id"`
	Name        string             `json:"name" binding:"required,min=1,max=255"`
	Description *string            `json:"description,omitempty" binding:"omitempty,max=1024"`
	Type        string             `json:"type"`
	AuthConfig  *models.AuthConfig `json:"auth_config"`
	Active      *bool              `json:"active"` // pointer to allow explicit false
}

// UpdatePrincipalRequest for updating a principal
type UpdatePrincipalRequest struct {
	Name        *string            `json:"name,omitempty"`
	Description *string            `json:"description,omitempty" binding:"omitempty,max=1024"`
	AuthConfig  *models.AuthConfig `json:"auth_config,omitempty"`
	Active      *bool              `json:"active,omitempty"`
}

// PrincipalResponse represents a principal
type PrincipalResponse struct {
	ID          string             `json:"id"`
	Name        string             `json:"name"`
	Description string             `json:"description,omitempty"`
	Type        string             `json:"type"`
	AuthConfig  *models.AuthConfig `json:"auth_config"`
	Active      bool               `json:"active"`
	CreatedAt   time.Time          `json:"created_at"`
	UpdatedAt   time.Time          `json:"updated_at"`
}

// ListPrincipalsResponse is the paginated response for listing principals
type ListPrincipalsResponse struct {
	resources.IterableList[PrincipalResponse]
}

// GrantPolicyRequest for assigning a policy to a principal
type GrantPolicyRequest struct {
	PolicyID  string `json:"policy_id" binding:"required"`
	GrantedBy string `json:"granted_by"`
}

// GrantPoliciesRequest for bulk assignment
type GrantPoliciesRequest struct {
	PolicyIDs []string `json:"policy_ids" binding:"required,min=1"`
	GrantedBy string   `json:"granted_by"`
}

// PrincipalPolicyResponse shows policy assignments
type PrincipalPolicyResponse struct {
	PrincipalID string    `json:"principal_id"`
	PolicyID    string    `json:"policy_id"`
	PolicyName  string    `json:"policy_name"`
	GrantedAt   time.Time `json:"granted_at"`
	GrantedBy   string    `json:"granted_by,omitempty"`
}

// ListPrincipalPoliciesResponse is the paginated response for listing a principal's policies
type ListPrincipalPoliciesResponse struct {
	PrincipalID string `json:"principal_id"`
	resources.IterableList[PrincipalPolicyResponse]
}
