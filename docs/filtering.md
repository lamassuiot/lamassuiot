# Filtering and JSONPath support ✅

## Overview

The API supports flexible server-side filtering and sorting on list endpoints using query parameters. Filters can operate on simple scalar fields (string, number, date, enum), arrays, and JSON fields. For JSON fields (`metadata`, `settings`, ...), you can use PostgreSQL JSONPath expressions for advanced queries and sorting.

---

## Query syntax (HTTP)

- Basic form: `?filter=<field>[<op>]<value>`
- Repeat `filter` to add multiple conditions (combined with AND).

Examples:

- `?filter=status[eq]=ACTIVE` — filter by equality on a string/enum field
- `?filter=tags[ct]=payments` — find elements where `tags` contains `payments`

Note: values must be URL-encoded when required (spaces, quotes, `>` etc.).

---

## Supported operators

| Operator | Meaning | Example (HTTP) |
|---|---:|---|
| `eq` | equal | `status[eq]=ACTIVE` |
| `eq_ic` | equal (case-insensitive) | `name[eq_ic]=alice` |
| `ne` | not equal | `status[ne]=REVOKED` |
| `ne_ic` | not equal (case-insensitive) | `name[ne_ic]=alice` |
| `ct` | contains (string) | `description[ct]=backup` |
| `ct_ic` | contains (case-insensitive) | `description[ct_ic]=backup` |
| `nc` | not contains | `description[nc]=skip` |
| `nc_ic` | not contains (case-insensitive) | `description[nc_ic]=skip` |
| `bf` | date before | `creation_date[bf]=2026-01-01` |
| `af` | date after | `creation_date[af]=2025-01-01` |
| `lt` | number less than | `size[lt]=1024` |
| `le` | number less or equal | `size[le]=1024` |
| `gt` | number greater than | `size[gt]=1024` |
| `ge` | number greater or equal | `size[ge]=1024` |
| `jsonpath` | JSONPath expression on a JSON field | see below |

These operators map to internal `resources.FilterOperation` values used by the SDK and server (see `core/pkg/resources/query.go`).

---

## JSONPath filtering (advanced)

- Use `field[jsonpath]<expression>` to filter JSON columns (e.g. `metadata`, `settings`).
- The expression is evaluated using PostgreSQL's `jsonpath` support (the server uses the `@@` operator).

Examples:

- Existence check: `?filter=metadata[jsonpath]exists($.environment)`
- String equality: `?filter=metadata[jsonpath]$.environment == "production"`
  - URL-encoded: `?filter=metadata[jsonpath]$.environment%20==%20%22production%22`
- Numeric comparison: `?filter=metadata[jsonpath]$.version > 1`

**Array operations:**

- Array contains value (simple array): `exists($.tags[*] ? (@ == "production"))`
- Array contains object with property: `exists($.tags[*] ? (@.key == "production"))`
- Array element by index: `$.tags[0] == "staging"`
- Array last element: `$.tags[last] == "backend"`
- Array numeric comparison: `exists($.ports[*] ? (@ > 8000))`
- Multiple array conditions (AND): `exists($.tags[*] ? (@ == "production")) && exists($.tags[*] ? (@ == "api"))`

Full HTTP examples:
```
?filter=metadata[jsonpath]exists($.tags[*] ? (@ == "production"))
?filter=metadata[jsonpath]$.tags[0] == "staging"
?filter=metadata[jsonpath]exists($.ports[*] ? (@ > 8000))
```

Notes:
- Array predicates use `[*]` iterator with `?` filter: `exists($.array[*] ? (condition))`
- `@` represents the current array element being tested
- For object arrays, access properties with `@.property`
- Direct index access: `[0]`, `[1]`, or `[last]` for the final element
- Combine conditions with `&&` (AND) or `||` (OR)
- Type-sensitive: comparisons behave according to JSON value types (strings vs numbers vs booleans)
- When using quotes or spaces, remember to URL-encode the query parameter

---

## SDK usage (Go)

Build `resources.QueryParameters` and add `resources.FilterOption` entries.

Example (JSONPath):

```go
qp := &resources.QueryParameters{
    PageSize: 25,
    Filters: []resources.FilterOption{
        {
            Field:           "metadata",
            Value:           `$.environment == "production"`,
            FilterOperation: resources.JsonPathExpression,
        },
    },
}

// pass qp to list calls (e.g. GetCertificates)
```

Example (simple equality):

```go
qp := &resources.QueryParameters{
    Filters: []resources.FilterOption{{
        Field: "status",
        Value: "ACTIVE",
        FilterOperation: resources.EnumEqual,
    }},
}
```

---

## Sorting ✅

### Basic Sorting

Sort results using `sort_by` and `sort_mode` query parameters:

- `?sort_by=<field>` — field to sort by
- `?sort_mode=asc|desc` — sort direction (default: `asc`)

**Examples:**

```http
# Sort devices by status ascending
GET /api/devmanager/v1/devices?sort_by=status&sort_mode=asc

# Sort certificates by creation date descending
GET /api/ca/v1/cas/{id}/certificates?sort_by=creation_ts&sort_mode=desc
```

### JSONPath Sorting

**New in 2026:** Sort by nested properties within JSON fields using JSONPath expressions.

**Syntax:** `?sort_by=<field>[jsonpath]<expression>&sort_mode=asc|desc`

**Examples:**

```http
# Sort devices by metadata.environment (alphabetically)
GET /api/devmanager/v1/devices?sort_by=metadata[jsonpath]$.environment&sort_mode=asc

# Sort devices by metadata.priority (numeric descending)
GET /api/devmanager/v1/devices?sort_by=metadata[jsonpath]$.priority&sort_mode=desc

# Sort by nested property (region within location)
GET /api/devmanager/v1/devices?sort_by=metadata[jsonpath]$.location.region&sort_mode=asc

# Sort by timestamp (chronological)
GET /api/devmanager/v1/devices?sort_by=metadata[jsonpath]$.created_at&sort_mode=asc
```

**URL-encoded format:**
```http
GET /api/devmanager/v1/devices?sort_by=metadata%5Bjsonpath%5D$.environment&sort_mode=asc
```

### Type-Aware Sorting

The system automatically detects and handles different data types in JSON fields:

| Type | Behavior | Example |
|---|---|---|
| **String** | Alphabetical sorting | `dev` → `prod` → `stage` |
| **Number** | Numeric sorting (not lexicographic) | `5` → `10` → `20` (not `10` → `20` → `5`) |
| **Date** | Chronological sorting (ISO 8601) | `2025-01-10` → `2025-06-20` → `2026-01-15` |
| **NULL/Missing** | ASC: last, DESC: first | Configurable with `NULLS FIRST/LAST` |

**Implementation:** Uses PostgreSQL CASE expressions to detect type and apply appropriate conversion:
- Numbers: Zero-padded to 20 digits for lexicographic comparison
- Dates: Detected by `YYYY-MM-DD` pattern, converted to sortable timestamp format
- Text: Direct string comparison

### SDK Usage (Go)

**Traditional sorting:**
```go
qp := &resources.QueryParameters{
    Sort: resources.SortOptions{
        SortMode:  resources.SortModeAsc,
        SortField: "status",
    },
}
```

**JSONPath sorting:**
```go
// Sort by string field
qp := &resources.QueryParameters{
    Sort: resources.SortOptions{
        SortMode:     resources.SortModeAsc,
        SortField:    "metadata",
        JsonPathExpr: "$.environment",
    },
}

// Sort by numeric field
qp := &resources.QueryParameters{
    Sort: resources.SortOptions{
        SortMode:     resources.SortModeDesc,
        SortField:    "metadata",
        JsonPathExpr: "$.priority",
    },
}

// Sort by nested property
qp := &resources.QueryParameters{
    Sort: resources.SortOptions{
        SortMode:     resources.SortModeAsc,
        SortField:    "metadata",
        JsonPathExpr: "$.location.region",
    },
}
```

### Combining Filters and Sorting

You can combine filtering and sorting in a single request:

```http
# Filter active devices and sort by priority
GET /api/devmanager/v1/devices?filter=status[eq]=ACTIVE&sort_by=metadata[jsonpath]$.priority&sort_mode=desc

# Filter by region and sort by environment
GET /api/devmanager/v1/devices?filter=metadata[jsonpath]$.region%20==%20%22us-west%22&sort_by=metadata[jsonpath]$.environment&sort_mode=asc
```

```go
qp := &resources.QueryParameters{
    Filters: []resources.FilterOption{
        {
            Field:           "status",
            Value:           "ACTIVE",
            FilterOperation: resources.EnumEqual,
        },
    },
    Sort: resources.SortOptions{
        SortMode:     resources.SortModeDesc,
        SortField:    "metadata",
        JsonPathExpr: "$.priority",
    },
}
```

### Pagination with Sorting

Sorting is preserved across pagination requests. The bookmark encodes the sort parameters:

```http
# First page
GET /api/devmanager/v1/devices?sort_by=metadata[jsonpath]$.priority&sort_mode=asc&page_size=10

# Response includes: next_bookmark=...
# Second page (bookmark maintains sort order)
GET /api/devmanager/v1/devices?bookmark=<encoded_bookmark>
```

The system ensures consistent ordering across all pages of results.

---

## Practical tips & caveats ⚠️

- Always URL-encode filter values when they contain spaces, quotes, or special characters.
- JSONPath filtering depends on PostgreSQL's `jsonpath` implementation — consult Postgres docs for expression semantics.
- Not all fields are filterable; check the resource-specific filter maps (e.g. `core/pkg/resources/*.go`) for allowed fields.
- For client libraries, prefer SDK helpers to encode filters properly; the SDK maps filter operations to short operator strings (e.g. `EnumEqual` -> `eq`, `JsonPathExpression` -> `jsonpath`).

---

## Where to look in the codebase

- Filter types and operations: `core/pkg/resources/query.go`
- SQL translation and JSONPath usage: `engines/storage/postgres/utils.go` (uses `field @@ ?::jsonpath` for JSONPath)
- End-to-end examples/tests: `backend/pkg/assemblers/tests/*/*_filter*.go` and `backend/pkg/assemblers/tests/ca/ca_certificates_test.go`

---

## Filterable fields by entity 🔎

Below is a concise list of the fields you can filter on for the main resources. The type column indicates how the server treats the value (String, Date, Number, Enum, JSON, StringArray).

### CA

| Field | Type | Notes |
|---|---:|---|
| `id` | String | |
| `level` | Number | |
| `type` | Enum | |
| `serial_number` | String | |
| `status` | Enum | |
| `engine_id` | String | |
| `valid_to` | Date | |
| `valid_from` | Date | |
| `revocation_timestamp` | Date | |
| `revocation_reason` | Enum | |
| `subject.common_name` | String | dotted path for nested subject fields |
| `subject_key_id` | String | |
| `profile_id` | String | |

### Certificate

| Field | Type | Notes |
|---|---:|---|
| `type` | Enum | |
| `serial_number` | String | |
| `subject.common_name` | String | |
| `subject_key_id` | String | |
| `issuer_meta.id` | String | dotted path to issuer metadata |
| `status` | Enum | |
| `engine_id` | String | |
| `valid_to` | Date | |
| `valid_from` | Date | |
| `revocation_timestamp` | Date | |
| `revocation_reason` | Enum | |
| `metadata` | JSON | Use `[jsonpath]` operator for advanced queries |

### Device

| Field | Type | Notes |
|---|---:|---|
| `id` | String | |
| `dms_owner` | String | |
| `creation_timestamp` | Date | |
| `status` | Enum | |
| `tags` | StringArray | use contains operators (`ct`, `ct_ic`) |
| `metadata` | JSON | Use `[jsonpath]` operator |

### DMS

| Field | Type | Notes |
|---|---:|---|
| `id` | String | |
| `name` | String | |
| `creation_date` | Date | |
| `metadata` | JSON | Use `[jsonpath]` operator |
| `settings` | JSON | Use `[jsonpath]` operator |

### KMS

| Field | Type | Notes |
|---|---:|---|
| `key_id` | String | |
| `engine_id` | String | |
| `has_private_key` | Enum | boolean-like enum |
| `algorithm` | String | |
| `size` | Number | |
| `public_key` | String | |
| `status` | String | |
| `creation_ts` | Date | |
| `name` | String | |
| `tags` | StringArray | |
| `metadata` | JSON | Use `[jsonpath]` operator |

### Issuance Profile

| Field | Type | Notes |
|---|---:|---|
| `id` | String | |
| `name` | String | |

> Tip: JSON fields (`metadata`, `settings`) are best queried with the `jsonpath` operator (e.g. `metadata[jsonpath]$.environment == "production"`).

---

## Endpoints that support filtering 🧭

Below are the main list endpoints that accept `filter` query parameters. Paths are shown with their API base for clarity; use the `filter` parameter as documented above.

### CA service
- GET /api/ca/v1/cas — list CAs
- GET /api/ca/v1/cas/{id}/certificates — list certificates for a CA

### KMS service
- GET /api/kms/v1/keys — list keys

### Device Manager
- GET /api/devmanager/v1/devices — list devices
- GET /api/devmanager/v1/devices/dms/{id} — list devices managed by a DMS

### DMS Manager
- GET /v1/dms (on /api/dmsmanager/v1) — list DMS instances

> Examples:
> - `GET /api/ca/v1/cas?filter=status[eq]=ACTIVE`
> - `GET /api/devmanager/v1/devices?filter=metadata[jsonpath]$.region%20==%20%22us-west-1%22`

