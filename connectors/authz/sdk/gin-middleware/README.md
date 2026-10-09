# Authorization contracts

The contract router covers all 134 registered routes across CA (34), KMS (13),
VA (5), Device Manager (19), Alerts (4), DMS Manager/EST (17) and Authz (42).
Authz includes 16 Envoy routes: eight methods on each of two paths. CONNECT is
intentionally not registered: it is a proxy tunnelling method, Envoy does not
forward it to ext_authz unless CONNECT is explicitly enabled, and OpenAPI 3 has
no standard CONNECT operation. A CONNECT request to these paths returns 404.
The external enrollment webhook has two outbound operations (POST and PUT),
tested through its real HTTP client against a local callback server.

The checks use ordinary Go tests and need no running demo, policies, sample data,
environment variables, or signed JWTs. Only the outbound webhook tests need a
local listening socket.

## Register validated permissions

```go
schemas, err := authz.PKISchemas()
if err != nil {
    panic(err)
}
certificate := middleware.MustNewAuthzMiddleware(
    engine, schemas, "pki", "ca", "certificate", logger,
)
contract := middleware.NewContractRouter(group)
rv1 := contract.Group("/v1")
rv1.POST("/certificates", certificate.Global("create"), createHandler)
rv1.GET("/certificates/:sn",
    certificate.Resource("read", map[string]string{"serial_number": "sn"}), getHandler)
rv1.GET("/certificates", certificate.List(), listHandler)
```

`GET`, `POST`, `PUT`, `PATCH` and `DELETE` are shorthands for `Handle`. A router
returned by `Group` records into the same contract, so the root router sees every
route, while `ValidateRoutes` on a sub-router checks only its own group.

`PKISchemas` embeds the canonical `connectors/authz/pki.json` and loads it through
the existing schema registry. `AuthzSchemas` embeds `authz.json` for the Authz
management API. The constructor rejects unknown entities and
namespaces. Permissions fail during route construction, before serving requests:

- `Global` requires a declared global action and sends no resource key.
- `Resource` requires a declared atomic action and maps every schema primary key
  to a path parameter. Registration rejects a parameter missing from the route.
- `ResourceCustom` resolves a path identifier into a composite key. It validates
  the action at registration and the exact primary key columns before authorizing.
  KMS uses this for PKCS#11 URIs and aliases, preserving resolver failures.
- `Public()` explicitly records anonymous access without invoking authorization.
  VA uses it for OCSP/CRL; EST uses it for CA certificates.
- `HandlerAuthorization("est" | "envoy" | "evaluation")` records checks performed
  inside the handler or service and adds no domain guard. Those declarations
  need dedicated protocol tests. Envoy and evaluation registrations also require
  an explicit trust boundary (see below). Authz evaluation calls carry credentials in
  their JSON body; the SDK does not add an Authorization header. Schema
  introspection retains its existing public access.
- `List` requires atomic `read` and attaches the existing authorization filter
  middleware. Its contract declares `check: filter` rather than an action check.

The permission's metadata and enforcing handler are private fields in one value.
`Handle` attaches that handler and records its declaration together.

## Require complete OpenAPI coverage

Every protected operation declares its namespace, schema, entity and action or filter:

```yaml
x-authz:
  namespace: pki
  schema_name: ca
  entity_type: certificate
  action: create
```

For list operations, replace `action: create` with `check: filter`.

Public operations declare `x-authz: {check: public}` and `security: []`.
The checker rejects public operations inheriting authentication, and protected
operations whose effective security permits anonymous access. Protected operations
inherit document-level security unless the operation overrides it; missing security,
empty arrays and any empty-object alternative are rejected. Every scheme named in a
document or operation `security` requirement must be defined in
`components.securitySchemes`, so a typo cannot pass as authentication. VA's server prefix is
`/api/va`: public paths are `/ocsp` and `/crl/{ca-ski}`, while role paths include
`/v1/roles/{ca-ski}`.

The backend contract tests construct each actual service router, then check:

1. `ValidateRoutes(router.Routes())`: every Gin route in the contract's group has
   a recorded permission, and every recorded route exists in Gin. A direct Gin
   registration bypassing the contract fails this check.
2. `ValidateOpenAPI(spec)`: every recorded route has a matching operation and
   `x-authz`, and every OpenAPI operation has a recorded route. Missing or extra
   operations and permission mismatches fail, even when the wrong permission is
   otherwise valid in the domain schema.

Run from the repository root:

```sh
go test ./connectors/authz/sdk/gin-middleware ./connectors/authz/pkg/api ./backend/pkg/routes ./backend/pkg/services -count=1
```

To print the coverage counts and the per-endpoint guard cases:

```sh
go test ./backend/pkg/routes ./connectors/authz/pkg/api -run 'Contract|OpenAPI' -count=1 -v
```

For every route protected by a domain guard, in-process HTTP tests verify
authentication failure and that the guard receives the recorded entity, action and primary key. Permission
checks deny with 403; an unavailable filter service stops list requests with 500.
KMS tests also verify URI and alias resolution, distinguish identical key IDs
in different engines, and reject malformed URIs or failed alias lookups before
authorization. SDK tests separately exercise allowed and denied global/resource
requests and filter propagation to the handler. These tests use a fake
authorization engine.
VA public tests call the actual controllers without credentials, using service
fakes and a valid OCSP request to verify anonymous OCSP/CRL responses.
Device Manager tests cover router construction with and without an SSE hub.
Event reads require device `read` for JSON and SSE; creating an event requires
`metadata-update`. Denied requests never open a stream. Group membership lists
filter devices, while group CRUD and statistics check device-group permissions.

Alerts tests cover event/subscription filters, global subscription creation and
unsubscribe by the subscription's domain key `id`, mapped from route `subId`.
DMS tests cover all nine management operations, including global `bind-identity`.
EST tests exercise all eight routes: CA certificate retrieval without JWTs and
service authorization failures for enrollment, reenrollment and server keygen.
The current controllers reject every EST variant without APS with 400; the tests
preserve that behavior. Existing EST controller tests cover successful enrollment.

Authz tests cover every management guard and exercise every Envoy route with
missing, matching and unmatched credentials against an in-memory HTTP policy.
Evaluation endpoints reject missing request bodies with 400. Webhook tests
cover allow/deny, missing or malformed decisions, non-success HTTP responses,
empty bodies and timeouts, and validate the outgoing CSR and request metadata.
The client sets JSON Content-Type and closes response bodies.

`TestEveryOpenAPISpecHasAnAssignedSuite` inventories the repository's OpenAPI
files, including documentation links. Adding a spec without assigning its test
suite fails. The DMS documentation copy must match its canonical tested spec.

## Trust boundaries

Envoy routes declare `internal-gateway`; Authz evaluation routes declare
`internal-service`. The boundary is separate from the handler's authorization
behavior:

```go
permission := middleware.HandlerAuthorization("envoy").WithTrustBoundary("internal-gateway")
contract.Handle(http.MethodGet, "/ext_authz/check", permission, checkHandler)
```

```yaml
x-authz:
  check: envoy
x-trust-boundary: internal-gateway
security: []
```

**A trust boundary currently equals public caller access.** It records intended
callers but does not restrict requests, authenticate Envoy/services, or validate
that forwarded credentials came from a trusted gateway. Anyone who can reach the
endpoint can call it. The handler still evaluates the submitted authorization
question; public caller access does not mean an allow decision.

This may change in the future: caller authentication or another restriction can
be added through `WithTrustBoundary`. No enforcement is configured today.
Contract tests verify matching boundary names in code and OpenAPI and require
explicit `security: []` so documentation reflects the current public access.
They do not prove network isolation or gateway identity. Ordinary anonymous
endpoints, such as CRL retrieval, remain `Public()` without a boundary.

## Scope

All currently bundled OpenAPI files have a coverage suite.
The OpenAPI checker supports direct OpenAPI 3 operations with a static
root-relative server prefix. It does not resolve path-item references or variable
servers.

The embedded schema is the build-time definition. These checks do not prove that
a deployed authorization service loaded the same schema, that its policies grant
the intended permissions, or that controllers apply filters correctly. Those
need integration tests against the demo. An application can inject a registry
loaded from configured schema files instead of using `PKISchemas`.
