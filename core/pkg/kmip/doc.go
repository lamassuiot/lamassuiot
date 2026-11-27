// Package kmip holds the KMIP vocabulary the KMS speaks internally: enumerations, and in later phases masks,
// parameters and lifecycle rules. Values are those of the KMIP Specification (§11), identical in 2.1 and 3.0.
//
// It imports only the standard library, so every layer (models, engines, services, endpoints) may import it.
package kmip
