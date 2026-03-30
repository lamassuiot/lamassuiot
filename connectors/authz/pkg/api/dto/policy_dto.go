package dto

import (
	"github.com/lamassuiot/authz/pkg/models"
)

// CreatePolicyRequest represents a request to create a new policy
type CreatePolicyRequest struct {
	ID          string         `json:"id" binding:"required"`
	Name        string         `json:"name" binding:"required"`
	Description string         `json:"description"`
	Rules       []*models.Rule `json:"rules" binding:"required,min=1"`
}

// UpdatePolicyRequest represents a request to update an existing policy
type UpdatePolicyRequest struct {
	Name        string         `json:"name" binding:"required"`
	Description string         `json:"description"`
	Rules       []*models.Rule `json:"rules" binding:"required,min=1"`
}

// PolicyResponse represents a policy in API responses
type PolicyResponse struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Rules       []*models.Rule `json:"rules"`
}

// PolicyListResponse represents a list of policies
type PolicyListResponse struct {
	Policies []*PolicyResponse `json:"policies"`
	Count    int               `json:"count"`
}

// PolicyStatsResponse represents policy statistics
type PolicyStatsResponse struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	RuleCount      int    `json:"ruleCount"`
	PrincipalCount int64  `json:"principalCount"`
	SizeBytes      int64  `json:"sizeBytes,omitempty"`
	LastModified   string `json:"lastModified,omitempty"`
}

// ToPolicyResponse converts a Policy to a PolicyResponse
func ToPolicyResponse(policy *models.Policy) *PolicyResponse {
	return &PolicyResponse{
		ID:          policy.ID,
		Name:        policy.Name,
		Description: policy.Description,
		Rules:       policy.Rules,
	}
}

// ToPolicyListResponse converts a slice of policies to PolicyListResponse
func ToPolicyListResponse(policies []*models.Policy) *PolicyListResponse {
	responses := make([]*PolicyResponse, len(policies))
	for i, policy := range policies {
		responses[i] = ToPolicyResponse(policy)
	}
	return &PolicyListResponse{
		Policies: responses,
		Count:    len(responses),
	}
}

// ToPolicy converts a CreatePolicyRequest to a Policy
func (r *CreatePolicyRequest) ToPolicy() *models.Policy {
	return &models.Policy{
		ID:          r.ID,
		Name:        r.Name,
		Description: r.Description,
		Rules:       r.Rules,
	}
}

// ApplyToPolicy applies an UpdatePolicyRequest to an existing Policy
func (r *UpdatePolicyRequest) ApplyToPolicy(policy *models.Policy) {
	policy.Name = r.Name
	policy.Description = r.Description
	policy.Rules = r.Rules
}
