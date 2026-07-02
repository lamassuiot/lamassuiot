package models

import coremodels "github.com/lamassuiot/lamassuiot/core/v3/pkg/models"

const AuthzSource = "service/authz"

const (
	EventCreatePrincipalKey  coremodels.EventType = "authz.principal.create"
	EventUpdatePrincipalKey  coremodels.EventType = "authz.principal.update"
	EventDeletePrincipalKey  coremodels.EventType = "authz.principal.delete"
	EventGrantPolicyKey      coremodels.EventType = "authz.principal.policy.grant"
	EventRevokePolicyKey     coremodels.EventType = "authz.principal.policy.revoke"

	EventCreatePolicyKey coremodels.EventType = "authz.policy.create"
	EventUpdatePolicyKey coremodels.EventType = "authz.policy.update"
	EventDeletePolicyKey coremodels.EventType = "authz.policy.delete"
)
