package core

type AuthzEngine interface {
	Authorize(principalID, namespace, schemaName, action, entityType string, entityKey map[string]string) (bool, error)
	GetFilter(principalID, namespace, schemaName, entityType string) (string, error)
	MatchAndAuthorize(authType, authMaterial, namespace, schemaName, action, entityType string, entityKey map[string]string) (bool, []string, error)
	MatchAndGetFilter(authType, authMaterial, namespace, schemaName, entityType string) (string, []string, error)
}
