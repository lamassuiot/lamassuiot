package authz

import (
	_ "embed"

	"github.com/lamassuiot/authz/pkg/engine"
)

// Embed the canonical file rather than maintaining another middleware schema.
//
//go:embed pki.json
var pkiSchema []byte

// PKISchemas loads the bundled domain definitions without a server or filesystem path.
// Applications can instead inject a registry loaded from their configured schema files.
func PKISchemas() (*engine.SchemaRegistry, error) {
	registry := engine.NewSchemaRegistry()
	if err := registry.LoadJSON(pkiSchema, "pki"); err != nil {
		return nil, err
	}
	return registry, nil
}

//go:embed authz.json
var authzSchema []byte

// AuthzSchemas loads the management API's own domain definitions.
func AuthzSchemas() (*engine.SchemaRegistry, error) {
	registry := engine.NewSchemaRegistry()
	if err := registry.LoadJSON(authzSchema, "authz"); err != nil {
		return nil, err
	}
	return registry, nil
}
