# Specification: Go Authorization Engine (Oso-Mimic)

## Overview

The goal is to build a high-performance authorization service in Go that allows for fine-grained permissions based on relationships between entities (e.g., "User A is an Editor of Folder B"). Like Twenty and Oso, this system must not only return true/false for single checks but also provide Query Filters to prevent "leaking" unauthorized data in list views.

## Core Data Models

### Entity Relations

Relations between entities are stored directly in the database through foreign keys defined in each entity's table. The authorization engine uses the schema definitions to know which foreign key columns to query.

**Example:**
- A device belongs to a gateway via `gateway_id` foreign key
- A gateway belongs to a building via `building_id` foreign key
- A building belongs to an organization via `organization_id` foreign key

### The Policy

The policy defines how permissions cascade through these foreign key relationships. Policies are JSON configuration files that specify which actions are allowed and how permissions flow through entity hierarchies.

**Entity addressing format (canonical):**
- Rules use `schemaName` + `entityType` fields.
- Relation targets use `to` as an object: `{ "schemaName": "...", "entityType": "..." }`.
- Backward compatibility: legacy string form (`"schema.entity"`) is NOT accepted for both rule `entityType` and relation `to`.

**Wildcard support when building policy rules:**
- Wildcards are supported for `actions`, rule `schemaName`, and rule `entityType`.
- Use `"*"` inside a rule or relation `actions` array to represent all actions defined by the target entity schema (`atomicActions ∪ globalActions`).
- Implementations MUST treat `"*"` in `actions` as a wildcard match during authorization/filter evaluation (equivalent to action expansion).
- Use `"*"` in rule `schemaName` and/or rule `entityType` to match all loaded schema names and/or entity types at policy compile time.
- Wildcards are **not** supported in `to.schemaName`, `to.entityType`, or `via`.
- During policy load/compile, `"*"` is expanded to concrete action names and duplicates are removed.
- During policy load/compile, wildcarded rule `schemaName`/`entityType` are expanded to concrete rule entries.
- Validation fails if any wildcard expansion produces no results (actions or matched rule entities).

Example (rule-level + relation-level wildcard):
```json
{
  "namespace": "iot",
  "schemaName": "public",
  "entityType": "organization",
  "actions": ["*"],
  "relations": [
    {
      "to": {
        "schemaName": "public",
        "entityType": "building"
      },
      "via": "parent",
      "actions": ["*"],
      "relations": []
    }
  ]
}
```

### Column Filters (Attribute-Based Scoping)

Rules can optionally include `columnFilters` to scope access to a subset of entities based on column values — useful for attribute-based access control (ABAC) alongside the relationship-based grants.

```json
{
  "namespace": "pki",
  "schemaName": "ca",
  "entityType": "certificate",
  "actions": ["read"],
  "columnFilters": [
    { "column": "status",   "type": "string",    "operator": "eq",   "value": "active" },
    { "column": "valid_to", "type": "timestamp", "operator": "gte",  "value": "2026-01-01" }
  ]
}
```

Each filter entry has the following fields:

| Field      | Required | Description |
|------------|----------|-------------|
| `column`   | yes | Column name — must be declared as `filterable` in the entity schema |
| `type`     | no  | Data type of the column (`string`, `int`, `float`, `bool`, `timestamp`, `jsonb`). When provided it is validated against the schema's `filterable` declaration and a mismatch causes a policy evaluation error. |
| `operator` | yes | Comparison operator (see table below) |
| `value`    | yes | Value to compare against; use a JSON array for `in` |

Multiple `columnFilters` entries are **ANDed** together. A column must be declared as `filterable` in the entity schema before it can be referenced (see [Schema Configuration](#schema-configuration-structure)).

#### Supported Filter Operators

| Operator | SQL | Applicable Types | Example |
|----------|-----|-----------------|---------|
| `eq`     | `=`      | all             | `{ "column": "status", "operator": "eq", "value": "active" }` |
| `neq`    | `!=`     | all             | `{ "column": "status", "operator": "neq", "value": "revoked" }` |
| `gt`     | `>`      | int, float, timestamp | `{ "column": "valid_to", "operator": "gt", "value": "2025-01-01" }` |
| `gte`    | `>=`     | int, float, timestamp | `{ "column": "valid_from", "operator": "gte", "value": "2024-01-01" }` |
| `lt`     | `<`      | int, float, timestamp | `{ "column": "retries", "operator": "lt", "value": 5 }` |
| `lte`    | `<=`     | int, float, timestamp | `{ "column": "retries", "operator": "lte", "value": 10 }` |
| `in`     | `IN`     | all             | `{ "column": "status", "operator": "in", "value": ["active", "pending"] }` |
| `like`   | `LIKE`   | string          | `{ "column": "subject_common_name", "operator": "like", "value": "device-%" }` |

#### Filterable Field Types

Columns declared as filterable in the schema carry a `type` that constrains which operators make semantic sense:

| Type        | Description | Recommended operators |
|-------------|-------------|-----------------------|
| `string`    | Text column | `eq`, `neq`, `in`, `like` |
| `int`       | Integer column | `eq`, `neq`, `gt`, `gte`, `lt`, `lte`, `in` |
| `float`     | Floating-point column | `eq`, `neq`, `gt`, `gte`, `lt`, `lte` |
| `bool`      | Boolean column | `eq`, `neq` |
| `timestamp` | Date/time column | `eq`, `neq`, `gt`, `gte`, `lt`, `lte` |
| `jsonb`     | JSON column (Postgres JSONB) | `eq`, `neq` |

> **Note:** The engine does not enforce type-operator compatibility at runtime — it generates SQL as-is. Invalid combinations (e.g., `LIKE` on an `int` column) will produce a database error. Schema authors are responsible for using compatible operators.

## Principals and Authentication

### Principal Types

The system supports two types of principals for authentication:

1. **OIDC User**: OpenID Connect authentication with claim-based matching
2. **X.509 Certificate**: PKI-based authentication with certificate validation

### Principal Data Structure

```json
{
  "id": "principal-uuid",
  "name": "human-readable-name",
  "type": "oidc|x509",
  "enabled": true,
  "auth_config": {
    // Type-specific authentication configuration
  },
  "created_at": "timestamp",
  "updated_at": "timestamp"
}
```

### Authentication Configuration by Type

#### OIDC User Principal

```json
{
  "type": "oidc",
  "auth_config": {
    "issuer": "https://accounts.google.com",
    "claims": [
      {
        "claim": "sub",
        "operator": "equals",
        "value": "user-1234567890"
      },
      {
        "claim": "email",
        "operator": "equals",
        "value": "alice@example.com"
      },
      {
        "claim": "groups",
        "operator": "contains",
        "value": "engineering"
      }
    ]
  }
}
```

**Matching Logic**: 
- Token must be issued by specified `issuer`
- All claim conditions must be satisfied (AND logic within a single principal)
- Supported operators:
  - `equals`: Exact match of claim value
  - `contains`: For array claims, checks if value is present in array
  - `matches`: Regex pattern matching (optional)

#### X.509 Certificate Principal

```json
{
  "type": "x509",
  "auth_config": {
    "ca_trust": {
      "pem": "<base64-encoded-PEM-string>",
      "identity_type": "fingerprint",
      "value": "SHA256:abc123..."
    },
    "serial_number": "1A:2B:3C:4D...",
    "subject_cn": "device-sensor-001.example.com",
    "match_mode": "serial_and_ca|cn_and_ca|any_from_ca"
  }
}
```
-----BEGIN CERTIFICATE-----
MIIDcTCCAxegAwIBAgIRAN/6WvrAIGea8IfUaiad0B8wCgYIKoZIzj0EAwIwgYgx
CzAJBgNVBAYTAkVTMREwDwYDVQQIEwhHaXB1emtvYTERMA8GA1UEBxMIQXJyYXNh
dGUxGjAYBgNVBAoTEUxhbWFzc3VJb1QgU2FtcGxlMRQwEgYDVQQLEwtEZXZlbG9w
bWVudDEhMB8GA1UEAxMYU2FtcGxlIEdlbmVyYXRlZCBSb290IENBMB4XDTI2MDIy
MDExNDQ0MloXDTM2MDIxODExNDQ0MlowDjEMMAoGA1UEAxMDZmZmMFkwEwYHKoZI
zj0CAQYIKoZIzj0DAQcDQgAEqk9N5KvJ0QvjXw33VRpAB37vcrNRl/VI8I0vHP6K
EPaYqtEBmkh7yvLk09ND0bEzbwwUrPvCNNKusXQl6ZIKq6OCAdkwggHVMA4GA1Ud
DwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MCkGA1UdDgQiBCCB017YND2VARiW
kD+eBaGjGWnsnqxVhBfb0Whm5iKClTArBgNVHSMEJDAigCC7BJ675LNwSqpvCP2V
Obe/eQDtk3Fw0BByMeENoLL2SzBzBggrBgEFBQcBAQRnMGUwNAYIKwYBBQUHMAGG
KGh0dHA6Ly9kZXYubGFtYXNzdS50ZXN0OjgwODAvYXBpL3ZhL29jc3AwLQYIKwYB
BQUHMAGGIWh0dHA6Ly9sb2NhbGhvc3Q6ODA4MC9hcGkvdmEvb2NzcDCB5AYDVR0f
BIHcMIHZMG6gbKBqhmhodHRwOi8vZGV2LmxhbWFzc3UudGVzdDo4MDgwL2FwaS92
YS9jcmwvYmIwNDllYmJlNGIzNzA0YWFhNmYwOGZkOTUzOWI3YmY3OTAwZWQ5Mzcx
NzBkMDEwNzIzMWUxMGRhMGIyZjY0YjBnoGWgY4ZhaHR0cDovL2xvY2FsaG9zdDo4
MDgwL2FwaS92YS9jcmwvYmIwNDllYmJlNGIzNzA0YWFhNmYwOGZkOTUzOWI3YmY3
OTAwZWQ5MzcxNzBkMDEwNzIzMWUxMGRhMGIyZjY0YjAKBggqhkjOPQQDAgNIADBF
AiEAv95Wmt2KH+YOCDymi8XIOqAKaitVcXaI5ZMIzv3nrOICIAcHf/ONgf6JTuYh
q8TME1/6AOdMqWZoJYr6wVz79Jnt
-----END CERTIFICATE-----

**Matching Logic**:
- `match_mode` determines matching strategy:
  - `serial_and_ca`: Certificate must have specific serial number AND be signed by specific CA
  - `cn_and_ca`: Certificate must have specific Common Name (CN) in subject AND be signed by specific CA
  - `any_from_ca`: Any certificate signed by the specified CA
- `ca_trust.pem` is mandatory and is used as the trusted CA certificate for signature verification during matching
- `ca_trust.identity_type` selects CA identity source:
  - `fingerprint`: `ca_trust.value` is the SHA-256 fingerprint of the DER-encoded CA certificate
  - `authority_key_id`: `ca_trust.value` is the CA Authority Key Identifier (AKI)
- Certificate chain validation is always performed

**Configuration Options**:
```json
// Option 1: Match specific certificate by serial + CA
{
  "match_mode": "serial_and_ca",
  "serial_number": "1A:2B:3C:4D:5E:6F",
  "ca_trust": {
    "pem": "<base64-encoded-PEM-string>",
    "identity_type": "fingerprint",   // fingerprint | authority_key_id
    "value": "SHA256:abc123..."
  }
}

// Option 2: Match by Common Name AND CA
{
  "match_mode": "cn_and_ca",
  "subject_cn": "sensor-*.example.com",  // Supports wildcards
  "ca_trust": {
    "pem": "<base64-encoded-PEM-string>",
    "identity_type": "fingerprint",   // fingerprint | authority_key_id
    "value": "SHA256:abc123..."
  }
}

// Option 3: Trust any cert from CA
{
  "match_mode": "any_from_ca",
  "ca_trust": {
    "pem": "<base64-encoded-PEM-string>",
    "identity_type": "fingerprint",   // fingerprint | authority_key_id
    "value": "SHA256:abc123..."
  }
}

// Option 4: Match by Common Name AND CA Authority Key Identifier (AKI)
{
  "match_mode": "cn_and_ca",
  "subject_cn": "sensor-*.example.com",  // Supports wildcards
  "ca_trust": {
    "pem": "<base64-encoded-PEM-string>",
    "identity_type": "authority_key_id",
    "value": "14AF9C22118B7E4A"
  }
}

// Option 5: Trust any cert from CA using Authority Key Identifier (AKI)
{
  "match_mode": "any_from_ca",
  "ca_trust": {
    "pem": "<base64-encoded-PEM-string>",
    "identity_type": "authority_key_id",
    "value": "14AF9C22118B7E4A"
  }
}
```

### Principal Matching Process

The authentication-to-principal matching occurs **before** any authorization checks (Check or ListFilter). This is the first stage of request processing:

```
Request → Extract Auth Material → Match Principal(s) → Authorize → Return Result
```

**Matching Algorithm**:

1. **Extract Authentication Material**:
   - OIDC: Parse and validate JWT from `Authorization: Bearer <jwt>`
   - X.509: Extract client certificate from mTLS connection

2. **Query All Enabled Principals**:
   - Filter by principal type matching the authentication method
   - Only consider `enabled: true` principals

3. **Match Against Each Principal**:
   - Apply type-specific matching logic (see above)
   - Collect all matching principals (0 or more)

4. **Handle Multiple Matches**:
   - If 0 matches: Authentication fails (401 Unauthorized)
   - If 1 match: Use that principal's ID for authorization
   - If 2+ matches: **Apply OR-based policy evaluation** (see below)

### Multi-Principal Authorization (OR Logic)

When multiple principals match the authentication material, the authorization engine evaluates permissions for **all matching principals** and combines results with OR logic:

```
Authorization Granted = (Principal_1 has permission) OR (Principal_2 has permission) OR ... OR (Principal_N has permission)
```

**Example Scenario**:
- User authenticates with OIDC token containing `sub: "alice"` and `groups: ["admin", "engineering"]`
- Two principals match:
  - Principal A: `sub equals "alice"`
  - Principal B: `groups contains "admin"`
- Authorization check for `read:device:sensor-101`:
  - Check if Principal A can read sensor-101 → Yes (via direct assignment)
  - Check if Principal B can read sensor-101 → No
  - **Result**: Access granted (OR logic)

**Implementation Notes**:
- Each principal maintains its own set of relationships to entities (via foreign keys)
- SQL queries are generated independently for each matching principal
- Final query combines all conditions with `OR`:
  ```sql
  WHERE (
    -- Principal A's permissions
    (assigned_technician_id = 'principal-a')
    OR
    -- Principal B's permissions
    (gateway_id IN (SELECT id FROM iot_gateways WHERE admin_id = 'principal-b'))
  )
  ```

### Database Schema for Principals

```sql
CREATE TABLE principals (
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
  type VARCHAR(50) NOT NULL CHECK (type IN ('oidc', 'x509')),
    enabled BOOLEAN DEFAULT true,
    auth_config JSONB NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_principals_type ON principals(type);
CREATE INDEX idx_principals_enabled ON principals(enabled);
CREATE INDEX idx_principals_auth_config ON principals USING gin(auth_config);
```

## System Architecture

The system operates in four stages:
1. **Authentication & Principal Matching**: Extract authentication material (JWT or certificate) and match against registered principals. Multiple principals may match.
2. **Context Injection**: Middleware identifies principal ID(s) from the authentication step.
3. **Filter Generation**: The engine evaluates entity schemas and policies to generate SQL WHERE clauses. If multiple principals match, combine their permissions with OR logic.
4. **SQL Modification**: The ORM (GORM) appends the authorization filter to the WHERE clause before executing queries.

### `pkg/authz` Main Files (ASCII Schema + Clear Responsibilities)

The following is the canonical module layout for the core authorization package. Each file MUST keep a single clear purpose.

```text
        +----------------------+
        |      service.go      |
        | API/service facade   |
        +----------+-----------+
             |
             v
        +----------------------+
        |      engine.go       |
        | Orchestration:       |
        | authorize/filter     |
        +----+------------+----+
             |            |
      uses         |            | uses
             v            v
        +----------------+   +----------------+
        |   filter.go    |<->|    graph.go    |
        | SQL filter gen |   | path discovery |
        +-------+--------+   +----------------+
          |
          | consumes
          v
        +----------------+
        |   policy.go    |
        | registry +      |
        | policy compile/ |
        | validation      |
        +----------------+

      +-------------------+                    +------------------------+
      |  policy_manager.go|                    | principal_manager.go   |
      | policy persistence|                    | principal auth matching|
      | (blob CRUD/stats) |                    | + grants in DB         |
      +---------+---------+                    +-----------+------------+
    |                                          |
    +--------------------+---------------------+
             |
             v
        +----------------------+
        |   capabilities.go    |
        | principal capability |
        | aggregation/report   |
        +----------------------+

        +----------------+
        |   schema.go    |
        | schema registry|
        | + entity meta  |
        +----------------+
```

#### File purpose contract (MUST)

- `engine.go`: only orchestration entrypoints (`Authorize`, `GetListFilter`) and DB execution wiring.
- `filter.go`: only SQL filter construction from schemas + policies + graph paths.
- `graph.go`: only authorization graph model and path-finding.
- `policy.go`: only in-memory policy registry, wildcard/rule matching, and shared policy validation/normalization helpers.
- `policy_manager.go`: only policy persistence (blob CRUD/list/stats). No independent policy validation logic; it MUST reuse `policy.go` shared validators.
- `principal_manager.go`: only principal persistence, principal-policy grant mappings, and auth material matching.
- `capabilities.go`: only capabilities projection/aggregation for principals from engine + managers.
- `schema.go`: only schema loading/validation/lookup utilities.
- `service.go`: only facade/glue implementing `core.AuthzEngine`; no heavy business rules.

#### Refactor rule for boundary clarity

- If logic validates/normalizes policy/rule/relation structures, it belongs in `policy.go` (shared helpers), not in `policy_manager.go`.
- If logic is storage-only for policies, it belongs in `policy_manager.go`.
- If logic builds SQL clauses, it belongs in `filter.go` (not in `engine.go` or `service.go`).

Current alignment note: duplicated policy validation has been consolidated to shared helpers in `policy.go` and reused by `policy_manager.go`.

## API Definition

### MatchPrincipal (auth_material, auth_type)
Matches authentication material to one or more principals.

**Input**:
- `auth_material`: The authentication data (JWT token or X.509 certificate)
- `auth_type`: Type of authentication ("oidc" or "x509")

**Output**:
```json
{
  "matched_principals": ["principal-id-1", "principal-id-2"],
  "auth_type": "oidc"
}
```

**Logic**:
1. Query all enabled principals of the specified type
2. Apply type-specific matching logic (claim validation or certificate validation)
3. Return array of all matching principal IDs
4. If empty array, authentication fails with 401

### Authorize (principals, action, object)
Performs a single "Yes/No" check when principal IDs are already known.

**Endpoints**:
- `POST /api/v1/authz/authorize` - Direct authorization with known principal IDs
- `POST /api/v1/authz/match/authorize` - Authorization with automatic principal matching from auth material

**Input (Direct)**:
- `principals`: Array of principal IDs (can be single or multiple)
- `action`: The action to check (e.g., "read", "write", "delete")
- `namespace`: The authorization namespace (e.g., `"iot"`)
- `schemaName`: The database schema (e.g., `"public"`)
- `entityType`: The entity type (e.g., `"device"`)
- `entityKey`: Map of PK column → value identifying the target entity (e.g., `{"device_id": "sensor-101"}` or `{"tenant_id": "acme", "device_id": "sensor-101"}`)
- `entityId` *(legacy, simple PK only)*: Bare string value; promoted to `entityKey` automatically when schema has a single-column PK

**Input (Match)**:
- `auth_material`: Authentication data (JWT or certificate)
- `auth_type`: Type of authentication ("oidc" or "x509")
- `action`: The action to check
- `namespace`, `schemaName`, `entityType`, `entityKey` / `entityId`: same as above

**Output**:
```json
{
  "allowed": true,
  "matched_principals": ["principal-id-1", "principal-id-2"]  // Only in /match/authorize
}
```

**Logic**: 
- **/match/authorize only**: First call MatchPrincipal to identify principal IDs from auth material
- For each principal ID, recursively traverse the entity hierarchy using foreign key relationships
- If checking access to a Device, look for direct ownership via foreign keys in that principal's relationships
- If none found, follow the parent relation (e.g., Gateway, then Building, then Organization) and check ownership at each level
- **If multiple principals**: Combine results with OR logic - access granted if ANY principal has permission
- Return `true` if at least one principal has access, otherwise `false`

### ListFilter (principals, action, objectType)
The "Oso-Mimic" special sauce. Instead of a boolean, it returns a Filter Object that can be applied to SQL queries.

**Endpoints**:
- `POST /api/v1/authz/filter` - Direct filtering with known principal IDs
- `POST /api/v1/authz/match/filter` - Filtering with automatic principal matching from auth material

**Input (Direct)**:
- `principals`: Array of principal IDs from MatchPrincipal step
- `action`: The action to filter by (e.g., "read")
- `objectType`: The entity type (e.g., "device")

**Input (Match)**:
- `auth_material`: Authentication data (JWT or certificate)
- `auth_type`: Type of authentication ("oidc" or "x509")
- `action`: The action to filter by
- `objectType`: The entity type

**Output**:
```json
{
  "in": ["task_1", "task_5", "task_10"],
  "or_where": { "workspace_id": "ws_99", "is_public": true },
  "matched_principals": ["principal-id-1", "principal-id-2"]  // Only in /match/filter
}
```

**Logic**:
- **/match/filter only**: First call MatchPrincipal to identify principal IDs from auth material
- Generate SQL WHERE conditions for each principal independently
- Combine all conditions with OR operator if multiple principals match
- Return unified filter that includes entities accessible by ANY matching principal

### Capabilities

The Capabilities API lets clients discover what a principal is allowed to do, split into two distinct queries with different semantics:

#### 1. Global Capabilities — `GetGlobalCapabilities(principal, ...)`

Returns **only the global actions** (those that do not require an entity ID, e.g. `create`, `list`) that are granted to a principal, grouped by entity type.  Atomic actions (`read`, `write`, `delete`, etc.) are **never** included in this response.

**Endpoints**:
- `POST /api/v1/authz/capabilities/global` — Direct query with a known principal ID
- `POST /api/v1/authz/match/capabilities/global` — Same but with automatic principal matching from auth material

**Input (Direct)**:
- `principal_id`: The principal whose capabilities are queried

**Input (Match)**:
- `auth_material`: Authentication data (JWT or certificate)
- `auth_type`: Type of authentication (`"oidc"` or `"x509"`)

**Output**:
```json
{
  "global_actions": {
    "iot.public.device":       ["create", "list"],
    "iot.public.gateway":      ["list"],
    "iot.public.organization": ["create", "list", "export"]
  },
  "matched_principals": ["principal-id-1"]
}
```
> Keys follow the format `<namespace>.<schema_name>.<entity_type>` (e.g. `"iot.public.device"`), where `namespace` is the config domain, `schema_name` is the PostgreSQL schema, and `entity_type` is the logical entity type.
> `matched_principals` is only present in the `/match/` variant.

**Logic**:
- **/match/ only**: First call MatchPrincipal to resolve principal IDs from auth material.
- Traverse the policy graph for each principal and collect every action that is classified as a `globalAction` in the schema for that entity type.
- Atomic actions are explicitly excluded — even if the principal holds them.
- Deduplicate and merge results across all matched principals (OR logic).
- Entity types with no granted global actions are omitted from the response.

---

#### 2. Entity Capabilities — `GetEntityCapabilities(principal, entityType, entityID, ...)`

Returns **only the atomic actions** (those that require an entity ID, e.g. `read`, `write`, `control`, `delete`) that are granted to a principal **on a specific entity instance**.  Global actions are **never** included in this response.

**Endpoints**:
- `POST /api/v1/authz/capabilities/entity` — Direct query with a known principal ID
- `POST /api/v1/authz/match/capabilities/entity` — Same but with automatic principal matching from auth material

**Input (Direct)**:
- `principal_id`: The principal whose capabilities are queried
- `namespace`: The authorization namespace / config domain (e.g. `"iot"`, `"pki"`)
- `schema_name`: The database schema the entity belongs to (e.g. `"public"`, `"ca"`)
- `entity_type`: The entity type within that schema (e.g. `"device"`, `"gateway"`)
- `entity_key`: Map of PK column → value (e.g. `{"device_id": "sensor-temp-101"}` or `{"tenant_id": "acme", "device_id": "sensor-101"}`)
- `entity_id` *(legacy, simple PK only)*: Bare string; promoted to `entity_key` automatically

**Input (Match)**:
- `auth_material`: Authentication data (JWT or certificate)
- `auth_type`: Type of authentication (`"oidc"` or `"x509"`)
- `namespace`, `schema_name`, `entity_type`, `entity_key` / `entity_id`: same as above

**Output**:
```json
{
  "namespace":  "iot",
  "schema_name": "public",
  "entity_type": "device",
  "entity_key":  { "device_id": "sensor-temp-101" },
  "actions":     ["read", "write", "control"],
  "matched_principals": ["principal-id-1"]
}
```
> `matched_principals` is only present in the `/match/` variant.
> `entity_id` (legacy string) continues to be echoed in responses for schemas with single-column PKs, alongside the new `entity_key` map.

**Logic**:
- **/match/ only**: First call MatchPrincipal to resolve principal IDs from auth material.
- Run the standard authorization traversal (same as `Authorize`) for every `atomicAction` defined in the schema identified by `namespace` + `schema_name` + `entity_type` against the given `entity_key`.
- Validate that `namespace` matches the config domain of the resolved schema (return error if not).
- Collect only those actions for which the result is `allowed = true`.
- Global actions are explicitly excluded — even if the principal holds them.
- Deduplicate and merge across all matched principals (OR logic).
- If no atomic actions are granted, return an empty `actions` array (do **not** return a 404).

---

#### Key Distinction: Global vs. Atomic Actions

| | Global Capabilities | Entity Capabilities |
|---|---|---|
| Requires `entity_key` input | No | Yes |
| Actions returned | `globalActions` only | `atomicActions` only |
| Typical actions | `create`, `list` | `read`, `write`, `delete`, `control` |
| Grouped by | Entity type | Single entity instance |

## Technical Requirements
### Inheritance Logic (ReBAC)
The engine must support inheritance through foreign key relationships:
- Direct Ownership: User owns entity via foreign key column (e.g., `organizations.owner_id`)
- Hierarchical Inheritance: Permissions on parent entities cascade to children through foreign key chains (e.g., Organization → Building → Gateway → Device)

### Storage
- Primary PostgreSQL for all entity storage with proper foreign key constraints.
- Cache: Redis for "Compiled Policies" and frequent "Authorize" checks.

### GORM Integration (The Twenty Approach)

The Go service should provide a gorm.Callback or similar that:
- Intercepts all Query operations.
- Calls the internal GetFilter method.
- Applies q.Where(...) to the GORM query builder before execution.

## Schema Definitions with Database Mappings

All entities in the system must be defined with explicit schema configurations that map to database tables and columns. This allows the authorization engine to query the database directly.

### Schema Configuration Structure

```json
{
  "entityType": "device",
  "tableName": "iot_devices",
  "primaryKey": "device_id",
  "relations": {
    "gateway": {
      "name": "gateway",
      "targetEntity": "gateway",
      "foreignKey": "gateway_id"
    }
  },
  "atomicActions": ["read", "write", "control", "delete"],
  "globalActions": ["create", "list"],
  "filterable": [
    { "column": "status",     "type": "string" },
    { "column": "created_at", "type": "timestamp" }
  ]
}
```

#### Composite Primary Keys

The `primaryKey` field accepts either a **single string** (simple PK) or a **JSON array of strings** (composite PK):

```json
// Simple primary key — string form (unchanged)
{
  "entityType": "device",
  "tableName": "iot_devices",
  "primaryKey": "device_id",
  ...
}

// Composite primary key — array form (new)
{
  "entityType": "tenant_device",
  "tableName": "tenant_devices",
  "primaryKey": ["tenant_id", "device_id"],
  ...
}
```

Both forms are valid. At schema load time the engine normalises a string value to a single-element array internally, so the rest of the engine always works with `[]string`.

#### Entity Key (entityKey)

Because a single `string` entityID cannot represent a composite primary key, all API endpoints and engine interfaces use a **key map** (`map[string]string`) instead of a bare string:

```json
// Simple PK — map with one entry
{ "device_id": "sensor-temp-101" }

// Composite PK — map with one entry per PK column
{ "tenant_id": "acme", "device_id": "sensor-101" }
```

At the SQL level, each entry generates one equality predicate ANDed together:
```sql
-- Simple
table.device_id = 'sensor-temp-101'

-- Composite
table.tenant_id = 'acme' AND table.device_id = 'sensor-101'
```

**Validation rules:**
- The keys of `entityKey` must be a subset of the columns declared in `primaryKey` for the targeted schema.
- All `primaryKey` columns must be present in `entityKey` for atomic-action checks (partial keys are rejected).
- When a schema uses a simple (string) `primaryKey`, callers may pass `entityKey` with a single entry whose key matches the declared column name, **or** may use the legacy `entityId` field (see backward compatibility below).

#### Backward Compatibility for Simple Primary Keys

To avoid a hard break for callers that use the existing `entityId: string` field, the API layer applies the following upgrade rule automatically **when the target schema has a single-column primary key**:

| Request contains | Behaviour |
|---|---|
| `entityKey` only | Used as-is |
| `entityId` only (legacy) | Promoted to `entityKey: { "<pk_column>": "<value>" }` |
| Both `entityKey` and `entityId` | `entityKey` takes precedence; `entityId` is ignored |

Schemas with **composite** primary keys reject requests that only supply a bare `entityId` string.

The `filterable` array declares which columns may appear in a rule's `columnFilters`. Any column not listed here will cause policy validation to fail when referenced in a filter. Each entry requires:

| Field    | Required | Description |
|----------|----------|-------------|
| `column` | yes | Exact column name in the database table |
| `type`   | yes | One of `string`, `int`, `float`, `bool`, `timestamp`, `jsonb` |

### Action Types

Schemas define two types of actions:

1. **atomicActions**: Operations that require an entity key to be checked against the database
   - Examples: `read`, `write`, `delete`, `control`, `update`
   - These actions check permissions on a specific, existing entity instance
   - Require an `entityKey` map (or legacy `entityId` string for simple PKs) in authorization requests

2. **globalActions**: Operations that don't require an existing entity
   - Examples: `create`, `list`
   - Used for operations like creating new entities or listing all accessible entities
   - Don't require entity ID in authorization requests

## IoT Domain Example

### Use Case: Smart Building Management System

A company manages smart buildings with the following hierarchy:
- Organizations own multiple Buildings
- Buildings contain multiple Gateways
- Gateways manage multiple Devices (sensors, actuators)
- Users have roles at different levels (org admin, building manager, device technician)

### Entity Schema Definitions

```json
[
  {
    "entityType": "organization",
    "tableName": "organizations",
    "primaryKey": "id",
    "relations": {
      "owner": {
        "name": "owner",
        "targetEntity": "principal",
        "foreignKey": "owner_id"
      }
    },
    "actions": ["read", "write", "delete"]
  },
  {
    "entityType": "building",
    "tableName": "buildings",
    "primaryKey": "id",
    "relations": {
      "organization": {
        "name": "organization",
        "targetEntity": "organization",
        "foreignKey": "organization_id"
      },
      "manager": {
        "name": "manager",
        "targetEntity": "principal",
        "foreignKey": "manager_id"
      }
    },
    "actions": ["read", "write", "delete"]
  },
  {
    "entityType": "gateway",
    "tableName": "iot_gateways",
    "primaryKey": "id",
    "relations": {
      "building": {
        "name": "building",
        "targetEntity": "building",
        "foreignKey": "building_id"
      }
    },
    "actions": ["read", "write", "configure", "delete"]
  },
  {
    "entityType": "device",
    "tableName": "iot_devices",
    "primaryKey": "device_id",
    "relations": {
      "gateway": {
        "name": "gateway",
        "targetEntity": "gateway",
        "foreignKey": "gateway_id"
      },
      "technician": {
        "name": "technician",
        "targetEntity": "principal",
        "foreignKey": "assigned_technician_id"
      }
    },
    "actions": ["read", "write", "control", "delete"]
  }
]
```

**How it works:**
- Each entity declares which actions are supported:
  - `atomicActions`: Actions requiring entity ID (e.g., `["read", "write", "control"]`)
  - `globalActions`: Actions not requiring entity ID (e.g., `["create", "list"]`)
- The authorization engine checks if the user has ownership via foreign key columns or inherits permissions from parent entities
- Foreign key relationships define the hierarchy for permission inheritance

### Policy Definitions

Policies determine how permissions cascade through entity relationships. The nested structure directly mirrors the hierarchy of permissions.

```json
[
  {
    "namespace": "iot",
    "schemaName": "public",
    "entityType": "organization",
    "actions": ["read", "write", "delete"],
    "relations": [
      {
        "to": {
          "schemaName": "public",
          "entityType": "building"
        },
        "via": "parent",
        "actions": ["read", "write", "delete"],
        "relations": [
          {
            "to": {
              "schemaName": "public",
              "entityType": "gateway"
            },
            "via": "parent",
            "actions": ["read", "write", "configure"],
            "relations": [
              {
                "to": {
                  "schemaName": "public",
                  "entityType": "device"
                },
                "via": "parent",
                "actions": ["read", "write", "control"]
              }
            ]
          }
        ]
      }
    ]
  },
  {
    "namespace": "iot",
    "schemaName": "public",
    "entityType": "building",
    "actions": ["read", "write", "delete"],
    "relations": [
      {
        "to": {
          "schemaName": "public",
          "entityType": "gateway"
        },
        "via": "parent",
        "actions": ["read", "write", "configure"],
        "relations": [
          {
            "to": {
              "schemaName": "public",
              "entityType": "device"
            },
            "via": "parent",
            "actions": ["read", "write", "control"]
          }
        ]
      }
    ]
  },
  {
    "namespace": "iot",
    "schemaName": "public",
    "entityType": "gateway",
    "actions": ["read", "write", "configure"],
    "relations": [
      {
        "to": {
          "schemaName": "public",
          "entityType": "device"
        },
        "via": "parent",
        "actions": ["read", "write", "control"]
      }
    ]
  },
  {
    "namespace": "iot",
    "schemaName": "public",
    "entityType": "device",
    "actions": ["read", "write", "control", "delete"],
    "relations": []
  }
]
```

**Policy Explanation:**

Each policy defines:
- **`namespace`**: Authorization namespace/config domain (e.g., `iot`, `pki`)
- **`schemaName`**: Database schema name for the rule entity (e.g., `public`, `ca`, `devicemanager`)
- **`entityType`**: Unqualified entity name this rule applies to (e.g., `device`, `organization`)
- **`actions`**: What actions can be performed directly on this entity (supports both atomic and global actions)
- **`relations`**: Nested array defining how permissions cascade to related entities
  - **`to`**: The target entity as object `{ schemaName, entityType }`
  - **`via`**: The relation name matching a foreign key defined in the schema (e.g., "organization", "building", "gateway")
  - **`actions`**: Which actions are granted on the target entity
  - **`relations`**: Recursive - can nest further to cascade through multiple levels

Legacy compatibility:
- `entityType: "schema.entity"` is NOT accepted.
- `to: "schema.entity"` is NOT accepted.
- New specs and examples use explicit `schemaName` fields.

**How Nesting Works:**

Given: User Alice has `owner_id` set in `organizations` table for organization `acme-corp`

The engine recursively evaluates:
1. Alice owns `organization:acme-corp` (via `owner_id` column) → can perform `["read", "write", "delete"]`
2. Follow nested relation `to: { schemaName: "public", entityType: "building" }` `via: "parent"` → Alice gets `["read", "write", "delete"]` on all buildings where `buildings.organization_id = 'acme-corp'`
3. Continue to nested `to: { schemaName: "public", entityType: "gateway" }` `via: "parent"` → Alice gets `["read", "write", "configure"]` on all gateways where `iot_gateways.building_id` matches those buildings
4. Continue to nested `to: { schemaName: "public", entityType: "device" }` `via: "parent"` → Alice gets `["read", "write", "control"]` on all devices where `iot_devices.gateway_id` matches those gateways

**Result:** Ownership at the organization level (via `owner_id` foreign key) cascades all the way down through the entire hierarchy automatically.

**Another Example:**

Given: User Eve has `assigned_technician_id` set for `device:sensor-101`

1. Eve owns `device:sensor-101` (via `assigned_technician_id` column) → can perform `["read", "write", "control", "delete"]`
2. Device has no nested relations in this context → permissions stop here
3. Result: Eve can only access this specific device, nothing else

### Sample Data in IoT Domain

```sql
-- Organizations
INSERT INTO organizations (id, name, owner_id) VALUES
  ('acme-corp', 'Acme Corporation', 'alice'),
  ('tech-inc', 'Tech Inc', 'frank');

-- Buildings
INSERT INTO buildings (id, name, organization_id, manager_id) VALUES
  ('hq-building', 'Headquarters Building', 'acme-corp', 'bob'),
  ('warehouse-1', 'Warehouse 1', 'acme-corp', NULL);

-- Gateways
INSERT INTO iot_gateways (id, name, building_id, ip_address, status) VALUES
  ('gw-floor1', 'Floor 1 Gateway', 'hq-building', '192.168.1.10', 'active'),
  ('gw-floor2', 'Floor 2 Gateway', 'hq-building', '192.168.1.11', 'active'),
  ('gw-warehouse', 'Warehouse Gateway', 'warehouse-1', '192.168.2.10', 'active');

-- Devices
INSERT INTO iot_devices (device_id, name, device_type, gateway_id, assigned_technician_id, status) VALUES
  ('sensor-temp-101', 'Temperature Sensor 101', 'sensor', 'gw-floor1', 'eve', 'active'),
  ('sensor-temp-102', 'Temperature Sensor 102', 'sensor', 'gw-floor1', NULL, 'active'),
  ('actuator-hvac-201', 'HVAC Actuator 201', 'actuator', 'gw-floor2', 'eve', 'active');
```

**Ownership Summary:**
- **Alice** owns organization `acme-corp` (via `organizations.owner_id`)
- **Bob** manages building `hq-building` (via `buildings.manager_id`)
- **Eve** is assigned to specific devices (via `iot_devices.assigned_technician_id`)

### Sample Principals

```sql
-- Principals table
INSERT INTO principals (id, name, type, enabled, auth_config) VALUES
  -- OIDC User for Alice (human user via SSO)
  ('principal-alice-oidc', 'Alice OIDC', 'oidc', true,
   '{"issuer": "https://accounts.google.com", "claims": [{"claim": "sub", "operator": "equals", "value": "google-oauth2|alice123"}]}'),
   
  -- OIDC Group-based principal for admins
  ('principal-admin-group', 'Admin Group', 'oidc', true,
   '{"issuer": "https://accounts.google.com", "claims": [{"claim": "groups", "operator": "contains", "value": "admins"}]}'),
   
  -- Bob's OIDC principal
  ('principal-bob-oidc', 'Bob Manager', 'oidc', true,
   '{"issuer": "https://auth.company.com", "claims": [{"claim": "email", "operator": "equals", "value": "bob@company.com"}]}'),
   
  -- Eve's certificate-based access (technician device)
  ('principal-eve-cert', 'Eve Technician Certificate', 'x509', true,
    '{"match_mode": "cn_and_ca", "subject_cn": "technician-eve.company.com", "ca_trust": {"pem": "<base64-encoded-PEM-string>", "identity_type": "fingerprint", "value": "SHA256:xyz789..."}}'),
   
  -- IoT Device certificate (any device from trusted CA)
  ('principal-iot-device-ca', 'IoT Device CA Trust', 'x509', true,
    '{"match_mode": "any_from_ca", "ca_trust": {"pem": "<base64-encoded-PEM-string>", "identity_type": "fingerprint", "value": "SHA256:abc123..."}}'),
   
  -- Specific gateway certificate
  ('principal-gateway-floor1', 'Gateway Floor 1 Certificate', 'x509', true,
    '{"match_mode": "serial_and_ca", "serial_number": "1A:2B:3C:4D:5E:6F", "ca_trust": {"pem": "<base64-encoded-PEM-string>", "identity_type": "fingerprint", "value": "SHA256:def456..."}}');

-- Update entity foreign keys to reference principals instead of simple user strings
-- Organizations now reference principal IDs
UPDATE organizations SET owner_id = 'principal-alice-oidc' WHERE id = 'acme-corp';

-- Buildings reference principal IDs
UPDATE buildings SET manager_id = 'principal-bob-oidc' WHERE id = 'hq-building';

-- Devices reference principal IDs
UPDATE iot_devices SET assigned_technician_id = 'principal-eve-cert' 
  WHERE device_id IN ('sensor-temp-101', 'actuator-hvac-201');
```

**Principal Matching Examples:**

1. **Alice authenticates with Google OAuth**:
   - JWT contains `iss: "https://accounts.google.com"`, `sub: "google-oauth2|alice123"`, `groups: ["admins"]`
   - **Matches**: `principal-alice-oidc` (sub match) AND `principal-admin-group` (groups contains "admins")
   - **Result**: Both principals are used for authorization with OR logic

2. **Eve connects with mTLS certificate**:
   - Certificate has CN: `technician-eve.company.com`
   - **Matches**: `principal-eve-cert` (CN match)
   - **Result**: Single principal used for authorization

3. **Gateway device connects with certificate**:
   - Certificate serial: `1A:2B:3C:4D:5E:6F`, signed by CA with fingerprint `SHA256:def456...`
   - **Matches**: `principal-gateway-floor1` (serial+CA match)
   - **Result**: Single principal used for authorization

4. **Unknown IoT device connects**:
   - Certificate signed by trusted IoT CA (`SHA256:abc123...`) but with random serial/CN
   - **Matches**: `principal-iot-device-ca` (any cert from CA)
   - **Result**: Single principal used for authorization

### Database Query Generation Examples

#### Example 1: List all devices Eve can read (with certificate authentication)

**Step 1 - Principal Matching:**
```json
{
  "auth_type": "x509",
  "certificate_cn": "technician-eve.company.com"
}
```
**Matched Principals**: `["principal-eve-cert"]`

**Step 2 - Authorization Request:**
```json
{
  "principals": ["principal-eve-cert"],
  "action": "read",
  "objectType": "device"
}
```

**Generated SQL Query:**
```sql
SELECT * FROM iot_devices WHERE (
    -- Direct ownership assignments via foreign key to principal
    assigned_technician_id = 'principal-eve-cert'
    
    OR
    
    -- Devices in gateways of buildings managed by this principal
    gateway_id IN (
        SELECT g.id FROM iot_gateways g
        JOIN buildings b ON g.building_id = b.id
        WHERE b.manager_id = 'principal-eve-cert'
    )
    
    OR
    
    -- Devices in gateways of buildings in organizations owned by this principal
    gateway_id IN (
        SELECT g.id FROM iot_gateways g
        JOIN buildings b ON g.building_id = b.id
        JOIN organizations o ON b.organization_id = o.id
        WHERE o.owner_id = 'principal-eve-cert'
    )
)
```

#### Example 2: Check if Alice can delete building (with multiple principal matches)

**Step 1 - Principal Matching:**
```json
{
  "auth_type": "oidc",
  "jwt_claims": {
    "iss": "https://accounts.google.com",
    "sub": "google-oauth2|alice123",
    "groups": ["admins", "engineering"]
  }
}
```
**Matched Principals**: `["principal-alice-oidc", "principal-admin-group"]`

**Step 2 - Authorization Request:**
```json
{
  "principals": ["principal-alice-oidc", "principal-admin-group"],
  "action": "delete",
  "object": "building:hq-building"
}
```

**Generated SQL Query (OR logic for multiple principals):**
```sql
SELECT EXISTS (
    -- Check if principal-alice-oidc owns the parent organization
    SELECT 1 FROM buildings b
    JOIN organizations o ON b.organization_id = o.id
    WHERE b.id = 'hq-building'
        AND o.owner_id = 'principal-alice-oidc'
        
    UNION
    
    -- Check if principal-alice-oidc is the direct manager
    SELECT 1 FROM buildings
    WHERE id = 'hq-building'
        AND manager_id = 'principal-alice-oidc'
        
    UNION
    
    -- Check if principal-admin-group owns the parent organization
    SELECT 1 FROM buildings b
    JOIN organizations o ON b.organization_id = o.id
    WHERE b.id = 'hq-building'
        AND o.owner_id = 'principal-admin-group'
        
    UNION
    
    -- Check if principal-admin-group is the direct manager
    SELECT 1 FROM buildings
    WHERE id = 'hq-building'
        AND manager_id = 'principal-admin-group'
) AS allowed
```

#### Example 3: List all gateways Bob can configure

**Step 1 - Principal Matching:**
```json
{
  "auth_type": "oidc",
  "jwt_claims": {
    "iss": "https://auth.company.com",
    "email": "bob@company.com"
  }
}
```
**Matched Principals**: `["principal-bob-oidc"]`

**Step 2 - Authorization Request:**
```json
{
  "principals": ["principal-bob-oidc"],
  "action": "configure",
  "objectType": "gateway"
}
```

**Generated SQL Query:**
```sql
SELECT * FROM iot_gateways WHERE (
    -- Gateways in buildings managed by bob's principal
    building_id IN (
        SELECT id FROM buildings
        WHERE manager_id = 'principal-bob-oidc'
    )
    
    OR
    
    -- Gateways in buildings of organizations owned by bob's principal
    building_id IN (
        SELECT b.id FROM buildings b
        JOIN organizations o ON b.organization_id = o.id
        WHERE o.owner_id = 'principal-bob-oidc'
    )
)
```

### IoT-Specific Authorization Scenarios

#### Scenario 1: Device Technician with Limited Scope (Certificate-based)
- **Eve** authenticates using an X.509 certificate with CN `technician-eve.company.com`
- Principal matching identifies `principal-eve-cert`
- This principal is assigned to specific devices via the `assigned_technician_id` foreign key
- She can read/write/control only her assigned devices (sensor-temp-101, actuator-hvac-201)
- She cannot access devices in other buildings or gateways
- Database: `iot_devices.assigned_technician_id = 'principal-eve-cert'`

#### Scenario 2: Building Manager (OIDC-based)
- **Bob** authenticates via OIDC with email `bob@company.com`
- Principal matching identifies `principal-bob-oidc`
- This principal manages "hq-building" via the `manager_id` foreign key
- He can read/write/configure all gateways and devices in that building
- Permissions cascade automatically through the nested policy structure
- Database: `buildings.manager_id = 'principal-bob-oidc'`
- Result: Bob gets access to all gateways where `iot_gateways.building_id = 'hq-building'`, and all devices in those gateways

#### Scenario 3: Organization Owner with Multiple Principals (OIDC with group membership)
- **Alice** authenticates via OIDC with `sub: "google-oauth2|alice123"` and `groups: ["admins"]`
- Principal matching identifies TWO principals: `principal-alice-oidc` AND `principal-admin-group`
- `principal-alice-oidc` owns "acme-corp" via the `owner_id` foreign key
- She has full permissions on all buildings, gateways, and devices in the organization
- Permissions cascade down through: organization → buildings → gateways → devices
- Database: `organizations.owner_id = 'principal-alice-oidc'`
- **OR Logic**: Even if `principal-admin-group` has no direct relationships, Alice still gets access via `principal-alice-oidc`
- Result: Alice has complete access to the entire hierarchy

#### Scenario 4: IoT Gateway Device (Certificate-based, CA trust)
- **Gateway gw-floor1** authenticates with certificate serial `1A:2B:3C:4D:5E:6F` signed by CA `SHA256:def456...`
- Principal matching identifies `principal-gateway-floor1`
- This principal could have permissions to read sensor data from its child devices
- Enables device-to-device authorization within the IoT hierarchy

#### Scenario 5: No Access
- **Charlie** attempts to authenticate with an OIDC token that does not match any principal
- Principal matching returns empty array
- Authentication fails with 401 Unauthorized
- Result: No access to any resources

#### Scenario 6: Multi-Principal Authorization (OR Logic)
- **Alice** authenticates via OIDC and matches both `principal-alice-oidc` and `principal-admin-group`
- Query for "list all buildings Alice can read":
  - Check buildings where `owner_id IN ('principal-alice-oidc', 'principal-admin-group')` at org level
  - Check buildings where `manager_id IN ('principal-alice-oidc', 'principal-admin-group')` direct
- Result: Union of all buildings accessible via EITHER principal

### Database Schema for IoT Example

```sql
-- Principals table (must be created first)
CREATE TABLE principals (
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
  type VARCHAR(50) NOT NULL CHECK (type IN ('oidc', 'x509')),
    enabled BOOLEAN DEFAULT true,
    auth_config JSONB NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_principals_type ON principals(type);
CREATE INDEX idx_principals_enabled ON principals(enabled);
CREATE INDEX idx_principals_auth_config ON principals USING gin(auth_config);

-- Entity tables with foreign keys referencing principals
CREATE TABLE organizations (
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    owner_id VARCHAR(255) REFERENCES principals(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE buildings (
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    organization_id VARCHAR(255) REFERENCES organizations(id),
    manager_id VARCHAR(255) REFERENCES principals(id),
    address TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE iot_gateways (
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    building_id VARCHAR(255) REFERENCES buildings(id),
    ip_address VARCHAR(45),
    status VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE iot_devices (
    device_id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    device_type VARCHAR(100),
    gateway_id VARCHAR(255) REFERENCES iot_gateways(id),
    assigned_technician_id VARCHAR(255) REFERENCES principals(id),
    status VARCHAR(50),
    last_reading JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_devices_gateway ON iot_devices(gateway_id);
CREATE INDEX idx_devices_technician ON iot_devices(assigned_technician_id);
CREATE INDEX idx_gateways_building ON iot_gateways(building_id);
CREATE INDEX idx_buildings_org ON buildings(organization_id);
CREATE INDEX idx_buildings_manager ON buildings(manager_id);
CREATE INDEX idx_orgs_owner ON organizations(owner_id);
```

**Key Changes from Simple User IDs:**
- All `owner_id`, `manager_id`, and `assigned_technician_id` columns now reference the `principals` table
- This enables support for multiple authentication methods (OIDC, X.509) while maintaining the same foreign key relationship structure
- The authorization engine queries the same way, but now works with principal IDs instead of simple user strings

## Summary: End-to-End Request Flow

### Complete Authorization Flow

```
1. HTTP Request arrives with authentication material
   ↓
2. Extract auth material based on type:
   - OIDC: Parse JWT from Authorization Bearer token
   - X.509: Extract client certificate from mTLS connection
   ↓
3. Match Principals (MatchPrincipal function):
   - Query principals table filtered by type and enabled=true
   - Apply type-specific matching logic:
     * OIDC: Issuer + claim validation (AND logic within principal)
     * X.509: Certificate validation based on match_mode
   - Collect ALL matching principals (0 to N)
   ↓
4. Authentication Result:
   - 0 matches → 401 Unauthorized
   - 1+ matches → Continue with principal ID(s)
   ↓
5. Authorization Check (Authorize or ListFilter):
   - For EACH matched principal:
     * Query entity hierarchy using foreign key relationships
     * Check direct ownership (e.g., owner_id, manager_id)
     * Check inherited permissions through parent entities
     * Generate SQL conditions for this principal
   - Combine all principals' conditions with OR logic
   ↓
6. Execute Query:
   - GORM applies combined WHERE clause
   - Returns only entities accessible by ANY matched principal
   ↓
7. Response with authorized data
```

### Key Design Principles

1. **Authentication ≠ Authorization**:
   - Authentication matches credentials to principals (MatchPrincipal)
   - Authorization checks what those principals can access (Authorize/ListFilter)
   - These are separate, sequential steps

2. **Multiple Principals = OR Logic**:
   - A single authentication can match multiple principals
   - Example: OIDC token with both specific user ID and group membership
   - Access granted if ANY principal has permission
   - SQL queries use UNION or multiple OR conditions

3. **Foreign Key-Based Relationships**:
   - All permissions flow through database foreign keys
   - Entities reference principals via `owner_id`, `manager_id`, etc.
   - No separate permission tables needed
   - Schema defines the hierarchy; policies define cascade rules

4. **Type-Specific Matching**:
   - **OIDC**: Flexible claim matching with operators (equals, contains, matches)
   - **X.509**: Multiple matching modes (serial+CA, CN, any-from-CA)
   - Each principal type has its own validation logic

5. **Hierarchical Permission Cascade**:
   - Policies define nested relationships
   - Ownership at higher levels (e.g., Organization) cascades down
   - SQL queries follow foreign key chains recursively
   - Performance optimized through proper indexing

### Implementation Checklist

- [ ] Create principals table with JSONB auth_config
- [ ] Implement MatchPrincipal function for all supported auth types (OIDC, X.509)
- [ ] Update entity tables to reference principals table
- [ ] Modify Authorize function to accept principal array
- [ ] Modify ListFilter function to generate OR-combined SQL
- [ ] Add middleware to extract auth material and match principals
- [ ] Implement OIDC claim validation (equals, contains operators)
- [ ] Implement X.509 certificate validation (all match modes)
- [ ] Add unit tests for multi-principal scenarios
- [ ] Add caching for principal matching results
- [ ] Document API endpoints for principal management (CRUD operations)
- [x] Support composite primary keys: `primaryKey` accepts `string` or `[]string`
- [x] Replace `entityId: string` with `entityKey: map[string]string` in all engine interfaces and API DTOs (with backward-compat promotion for simple-PK schemas)
- [x] SQL generation for composite PKs: AND-combine one equality condition per key column
- [x] Schema validation: reject schemas whose composite `primaryKey` contains duplicate or empty column names
