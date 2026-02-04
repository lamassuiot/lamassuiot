# RFC-008: Filtered Statistics Endpoints

| Status | Implemented |
|:---|:---|
| **Date** | 2026-01-29 |
| **Authors** | Engineering Team |
| **Focus** | CA Service, DMS Manager, KMS, Device Manager, API Consistency |
| **Implementation Status** | ✅ Phase 5 Complete (2026-01-30) |

## 1. Abstract

This RFC proposes extending the statistics endpoints across all Lamassu services to support query-based filtering. Currently, the Device Manager service's `/stats` endpoint accepts filter parameters via `QueryParameters`, enabling users to retrieve statistics for a specific subset of devices. This functionality must be extended to the CA Service (for both CAs and Certificates), DMS Manager, and KMS to provide a consistent API experience and enable dashboard/reporting use cases that require filtered aggregate statistics.

## 2. Motivation

As PKI deployments grow, operators need visibility into specific subsets of their infrastructure. Common use cases include:

- **Segmented Monitoring**: "Show me certificate statistics for CAs tagged with `environment:production`."
- **Compliance Reporting**: "Count certificates by status for CAs in a specific engine."
- **Fleet Analytics**: "How many DMS instances have specific metadata properties?"
- **Key Management Insights**: "How many RSA keys exist in the AWS KMS engine?"
- **Dashboard Widgets**: Custom dashboard widgets that display counts for filtered resource sets.

Currently, the Device Manager's `GetDevicesStats` endpoint already supports filtering:
- Users can pass any valid device filter (except `status`, which is always computed as a distribution).
- The endpoint returns total device count and status distribution for the filtered set.

However, other services have gaps:
- **CA Service**: `GET /v1/stats` and `GET /v1/stats/{id}` return global statistics with no filter support.
- **DMS Manager**: `GET /v1/stats` returns only `TotalDMSs` with no filter support.
- **KMS**: No statistics endpoint exists at all.

This inconsistency limits the usefulness of the statistics API for advanced monitoring scenarios.

## 3. Goals

1. **Extend filtering to CA statistics**: Allow filtering CAs by metadata, engine, level, profile, and other fields.
2. **Extend filtering to Certificate statistics**: Allow filtering certificates by CA, metadata, expiration, and other fields.
3. **Extend filtering to DMS statistics**: Allow filtering DMS instances by metadata and other fields.
4. **Add KMS statistics endpoint**: Create a new stats endpoint for keys with filtering support from inception.
5. **Maintain backward compatibility**: Existing API calls without filters should continue to work unchanged.
6. **Consistent behavior**: The `status` field should not be accepted as a filter on stats endpoints; status distribution is always returned for the matching set.

## 4. Non-Goals

1. Custom aggregation functions (e.g., average validity period).
2. Time-series statistics or historical data.
3. Cross-service statistics (e.g., devices per CA).
4. Real-time streaming statistics.

## 5. Services Overview

| Service | Stats Endpoint | Current Filtering | This RFC |
|---------|---------------|-------------------|----------|
| Device Manager | `GET /v1/stats` | ✅ Implemented | Reference implementation |
| CA Service | `GET /v1/stats`, `GET /v1/stats/{id}` | ❌ Not implemented | Add filtering |
| DMS Manager | `GET /v1/stats` | ❌ Not implemented | Add filtering |
| KMS | None | N/A | Add stats endpoint with filtering |

## 6. Current State Analysis

### 6.1 Device Manager (Reference Implementation)

The Device Manager already implements filtered statistics correctly. The key design patterns are:

1. **Input Structure**: The `GetDevicesStatsInput` struct accepts optional `QueryParameters` for filtering.
2. **Controller Layer**: The controller parses HTTP query parameters using the shared `FilterQuery()` helper function with `DeviceFilterableFields`.
3. **Validation**: The service rejects any filter on the `status` field, returning a 400 Bad Request error.
4. **Counting Logic**: For each possible status value, the service combines the user's filters with a status filter and counts matching devices. The total count uses only the user's base filters.
5. **Response**: Returns `DevicesStats` containing `TotalDevices` and `DevicesStatus` (map of status to count).

### 6.2 CA Service (Current State)

**Current Response Model** (`CAStats`):
- `CACertificatesStats`: Contains `TotalCAs`, `CAsDistributionPerEngine` (map of engine ID to count), and `CAsStatus` (map of status to count).
- `CertificatesStats`: Contains `TotalCertificates`, `CertificateDistributionPerCA` (map of CA ID to count), and `CertificateStatus` (map of status to count).

**Current Limitations**:
- The `GetStats` method accepts no input parameters—it always returns global statistics.
- The `GetStatsByCAID` method only accepts a CA ID, not additional filters for certificates within that CA.
- No ability to filter CAs by metadata, engine, profile, or other properties.

### 6.3 DMS Manager (Current State)

**Current Response Model** (`DMSStats`):
- Contains only `TotalDMSs` (integer count).

**Current Limitations**:
- The `GetDMSStatsInput` struct is empty—no parameters accepted.
- No ability to filter DMS instances by name, metadata, or settings.

### 6.4 KMS (Current State)

**No Statistics Endpoint Exists**

The KMS service manages cryptographic keys with properties including: `KeyID`, `Name`, `Aliases`, `EngineID`, `HasPrivateKey`, `Algorithm`, `Size`, `PublicKey`, `CreationTS`, `Tags`, and `Metadata`.

The service interface includes methods for key CRUD operations and signing/verification, but no statistics method. The routes file has no `/stats` endpoint.

## 7. Proposed Changes

### 7.1 CA Service Changes

#### 7.1.1 Service Interface Changes

**File**: `core/pkg/services/ca.go`

| Change | Description |
|--------|-------------|
| New struct `GetStatsInput` | Add two fields: `CAQueryParameters` and `CertificateQueryParameters`, both of type `*resources.QueryParameters`. These allow independent filtering of CAs and certificates. |
| Modify `GetStats` signature | Change from `GetStats(ctx context.Context) (*models.CAStats, error)` to accept the new `GetStatsInput` struct. |
| Modify `GetStatsByCAIDInput` | Add field `CertificateQueryParameters *resources.QueryParameters` to allow filtering certificates within a specific CA. |

#### 7.1.2 Service Implementation Changes

**File**: `backend/pkg/services/ca.go`

| Change | Description |
|--------|-------------|
| Status filter validation | Before processing, validate that neither `CAQueryParameters` nor `CertificateQueryParameters` contains a filter on the `status` field. Return `ErrValidateBadRequest` if found. |
| Engine distribution counting | When counting CAs per engine, apply the CA filters to each engine count query. |
| CA status distribution | For each status (Active, Expired, Revoked), combine user's CA filters with a status filter and count. |
| Total CA count | Count CAs matching only the user's CA filters (without status). |
| Certificate status distribution | For each status, combine user's certificate filters with a status filter and count. |
| Total certificate count | Count certificates matching only the user's certificate filters. |

**Expected Behavior for `GetStats`**:

1. **When called with no filters**: The service retrieves global statistics across all CAs and all certificates. It iterates through all registered crypto engines, counting CAs in each. It computes status distribution by counting CAs in each status state (Active, Expired, Revoked). The same logic applies independently to certificates. The response contains totals and distributions for the entire PKI.

2. **When called with CA filters only**: The service applies the CA filter to all CA-related counts. Only CAs matching the filter are counted in totals and status distributions. The engine distribution includes only matching CAs. Certificate statistics remain unfiltered—they represent all certificates across all CAs, not just certificates belonging to filtered CAs.

3. **When called with certificate filters only**: CA statistics remain unfiltered—totals and distributions cover all CAs. Certificate statistics apply the filter: only matching certificates appear in counts and status distributions. The per-CA distribution counts only matching certificates within each CA.

4. **When called with both CA and certificate filters**: Both filters are applied independently to their respective resource types. CA filters affect CA counts; certificate filters affect certificate counts. There is no implicit relationship—filtering CAs does not automatically filter certificates to those CAs.

5. **Error scenarios**: If either filter contains a `status` field, reject immediately with HTTP 400 and a clear error message explaining that status cannot be filtered because the status distribution is always computed. If a filter references an unknown field, reject with HTTP 400 listing valid field names.

#### 7.1.3 Controller Changes

**File**: `backend/pkg/controllers/ca.go`

| Change | Description |
|--------|-------------|
| Add new helper function | Create `FilterQueryWithPrefix()` or use parameter naming convention to parse CA filters (prefixed with `ca_`) separately from certificate filters (prefixed with `cert_`). |
| Modify `GetStats` handler | Parse `ca_filter` query parameters using `CAFilterableFields` and `cert_filter` using `CertificateFilterableFields`. Pass both to the service. |
| Modify `GetStatsByCAID` handler | Parse certificate filter parameters and pass to the service along with the CA ID. |

**Expected Behavior for Controller**:

1. **Parsing dual-prefix filters**: The controller examines query parameters looking for `ca_filter` and `cert_filter` keys. Each key may appear multiple times (for multiple filter conditions). The controller parses each prefix independently using the appropriate filterable fields map. If `ca_filter` is absent, the CA query parameters are nil. If `cert_filter` is absent, the certificate query parameters are nil.

2. **Validation failure handling**: If parsing fails (malformed expression or unknown field), the controller immediately returns HTTP 400 with a JSON error body containing the specific validation error message. The service is not called.

3. **Successful parsing**: Both parsed query parameters (which may be nil) are packaged into `GetStatsInput` and passed to the service. The controller awaits the service response.

4. **Service error handling**: If the service returns an error (such as status filter rejection), the controller maps the error to the appropriate HTTP status code using the existing error mapping logic and returns the error response.

5. **Success response**: On success, the controller serializes the `CAStats` model to JSON and returns HTTP 200.

#### 7.1.4 API Behavior

| Endpoint | Parameters | Behavior |
|----------|------------|----------|
| `GET /v1/stats` | None | Returns global statistics (backward compatible) |
| `GET /v1/stats?ca_filter=...` | CA filter expression | Returns statistics for matching CAs only |
| `GET /v1/stats?cert_filter=...` | Certificate filter expression | Returns statistics for matching certificates only |
| `GET /v1/stats?ca_filter=...&cert_filter=...` | Both | Returns statistics with both filters applied independently |
| `GET /v1/stats/{id}?cert_filter=...` | CA ID + certificate filter | Returns certificate status distribution for the CA, filtered |

**Example Queries**:
- `GET /v1/stats?ca_filter=engine_id[eq]aws-kms-prod` - Stats for CAs in a specific engine
- `GET /v1/stats?ca_filter=metadata[jsonpath]$.environment == "production"` - Stats for production CAs
- `GET /v1/stats?cert_filter=valid_from[after]2026-01-01T00:00:00Z` - Stats for recently issued certificates

### 7.2 DMS Manager Changes

#### 7.2.1 Service Interface Changes

**File**: `core/pkg/services/dmsmanager.go`

| Change | Description |
|--------|-------------|
| Modify `GetDMSStatsInput` | Add field `QueryParameters *resources.QueryParameters` to the currently empty struct. |

#### 7.2.2 Service Implementation Changes

**File**: `backend/pkg/services/dmsmanager.go`

| Change | Description |
|--------|-------------|
| Counting with filters | Replace the call to `dmsStorage.Count()` with `dmsStorage.CountWithFilters()` passing the query parameters. |
| Nil handling | If `QueryParameters` is nil, count all DMS instances (backward compatible). |

**Expected Behavior for `GetDMSStats`**:

1. **When called with no filters**: The service counts all DMS instances in the storage and returns `DMSStats` with `TotalDMSs` set to the complete count. This matches the current behavior exactly.

2. **When called with a filter**: The service passes the filter to the storage layer, which applies it to the query. Only DMS instances matching all filter conditions are counted. The response contains the filtered count in `TotalDMSs`.

3. **Filter examples**: A filter like `name[contains]production` counts only DMS instances whose name contains "production". A JSONPath filter like `metadata[jsonpath]$.region == "eu-west-1"` counts only DMS instances with that metadata value.

4. **Error scenarios**: If the filter references an unknown field (not in `DMSFilterableFields`), reject with HTTP 400 and list valid field names. Unlike CA and Device Manager, there is no status field to reject because DMS does not have a status property.

#### 7.2.3 Controller Changes

**File**: `backend/pkg/controllers/dmsmanager.go`

| Change | Description |
|--------|-------------|
| Parse filter parameters | Use `FilterQuery()` helper with `DMSFilterableFields` to parse HTTP query parameters. |
| Pass to service | Include parsed parameters in the `GetDMSStatsInput` struct. |

**Expected Behavior for Controller**:

1. **No filter provided**: If the request has no `filter` query parameter, the controller creates `GetDMSStatsInput` with nil `QueryParameters` and calls the service. The service treats this as "count all."

2. **Filter provided**: The controller calls `FilterQuery()` with the request context and `DMSFilterableFields`. If parsing succeeds, it creates `GetDMSStatsInput` with the parsed parameters.

3. **Invalid filter**: If `FilterQuery()` returns an error (unknown field or malformed syntax), the controller returns HTTP 400 with the error message in the response body.

4. **Service call and response**: On successful parsing, the controller calls the service and returns the `DMSStats` response as JSON with HTTP 200.

#### 7.2.4 API Behavior

| Endpoint | Parameters | Behavior |
|----------|------------|----------|
| `GET /v1/stats` | None | Returns total DMS count (backward compatible) |
| `GET /v1/stats?filter=...` | Filter expression | Returns count of matching DMS instances |

**Example Queries**:
- `GET /v1/stats?filter=metadata[jsonpath]$.region == "eu-west-1"` - Count DMS in EU region
- `GET /v1/stats?filter=name[contains]production` - Count production DMS instances

### 7.3 KMS Service Changes

The KMS service requires a completely new statistics endpoint.

#### 7.3.1 New Model

**File**: `core/pkg/models/kms.go`

| New Type | Fields | Description |
|----------|--------|-------------|
| `KeyStats` | `TotalKeys` (int) | Total number of keys matching the filter |
| | `KeysDistributionPerEngine` (map[string]int) | Count of keys per crypto engine |
| | `KeysDistributionPerAlgorithm` (map[string]int) | Count of keys per algorithm (RSA, ECDSA, Ed25519) |

#### 7.3.2 Service Interface Changes

**File**: `core/pkg/services/kms.go`

| Change | Description |
|--------|-------------|
| New struct `GetKeyStatsInput` | Contains `QueryParameters *resources.QueryParameters` for filtering. |
| Add method to `KMSService` | Add `GetKeyStats(ctx context.Context, input GetKeyStatsInput) (*models.KeyStats, error)` to the interface. |

#### 7.3.3 Service Implementation

**File**: `backend/pkg/services/kms.go`

| Requirement | Description |
|-------------|-------------|
| Total count | Count all keys matching the user's filters. |
| Engine distribution | For each registered crypto engine, count keys matching filters AND belonging to that engine. |
| Algorithm distribution | For each algorithm type (RSA, ECDSA, Ed25519), count keys matching filters AND using that algorithm. Use a helper function to add algorithm filter to existing parameters. |
| Error handling | On count errors, set the value to -1 and log the error (don't fail the entire request). |

**Expected Behavior for `GetKeyStats`**:

1. **When called with no filters**: The service computes statistics across all keys in the system. It retrieves the list of registered crypto engines and counts keys in each. It counts keys by algorithm type (RSA, ECDSA, Ed25519). The response includes `TotalKeys` as the complete count, `KeysDistributionPerEngine` as a map from engine ID to count, and `KeysDistributionPerAlgorithm` as a map from algorithm name to count.

2. **When called with a filter**: All counts are computed against the filtered set of keys. The total reflects only matching keys. Engine distribution counts only matching keys within each engine. Algorithm distribution counts only matching keys of each algorithm type. For example, filtering by `engine_id[eq]aws-kms-prod` would show zero keys for other engines in the distribution.

3. **Computing engine distribution**: The service iterates through all crypto engines registered in the system. For each engine, it calls the storage layer to count keys where the engine ID matches AND the user's filter conditions are satisfied. Engines with zero matching keys appear in the distribution with a count of zero.

4. **Computing algorithm distribution**: The service defines a fixed list of algorithm types (RSA, ECDSA, Ed25519). For each algorithm, it constructs a combined filter that includes the user's filters AND an algorithm filter. It counts matching keys and populates the distribution map.

5. **Error handling during counting**: If counting fails for a specific engine or algorithm (for example, due to a database error), the service sets that count to -1, logs the error with context, and continues processing other counts. The request does not fail entirely because partial statistics are still valuable. The caller can identify failed counts by the -1 value.

6. **Error scenarios**: If the filter references an unknown field (not in `KeyFilterableFields`), reject with HTTP 400 listing valid field names. Unlike CA and Device Manager stats, there is no status field restriction because keys do not have a status property with distribution semantics.

#### 7.3.4 Controller

**File**: `backend/pkg/controllers/kms.go`

| Change | Description |
|--------|-------------|
| New method `GetStats` | Parse filter parameters using `FilterQuery()` with `KeyFilterableFields`. Call service and return JSON response. |

**Expected Behavior for Controller**:

1. **No filter provided**: If the request has no `filter` query parameter, create `GetKeyStatsInput` with nil `QueryParameters`. The service will compute statistics across all keys.

2. **Filter provided**: Call `FilterQuery()` with `KeyFilterableFields` to parse the filter expression. On success, create `GetKeyStatsInput` with the parsed parameters.

3. **Invalid filter**: If parsing fails due to unknown field or malformed syntax, return HTTP 400 with a descriptive error message listing valid fields from `KeyFilterableFields`.

4. **Service response handling**: Call `GetKeyStats` on the service. If successful, serialize `KeyStats` to JSON and return HTTP 200. If the service returns an error, map it to the appropriate HTTP status code.

#### 7.3.5 Route Registration

**File**: `backend/pkg/routes/kms.go`

| Change | Description |
|--------|-------------|
| Add stats route | Register `GET /v1/stats` before existing routes, mapping to `routes.GetStats`. |

#### 7.3.6 Filterable Fields

**File**: `core/pkg/resources/fields.go`

| Change | Description |
|--------|-------------|
| Add `KeyFilterableFields` | Define filterable fields for keys: `key_id` (String), `name` (String), `engine_id` (String), `algorithm` (String), `size` (Number), `creation_ts` (Date), `tags` (StringArray), `metadata` (Json). |

#### 7.3.7 API Behavior

| Endpoint | Parameters | Behavior |
|----------|------------|----------|
| `GET /v1/stats` | None | Returns statistics for all keys |
| `GET /v1/stats?filter=...` | Filter expression | Returns statistics for matching keys |

**Example Queries**:
- `GET /v1/stats?filter=engine_id[eq]aws-kms-prod` - Stats for keys in AWS KMS
- `GET /v1/stats?filter=algorithm[contains]RSA` - Stats for RSA keys
- `GET /v1/stats?filter=metadata[jsonpath]$.purpose == "signing"` - Stats for signing keys
- `GET /v1/stats?filter=creation_ts[after]2026-01-01T00:00:00Z` - Stats for recently created keys

### 7.4 Storage Layer Changes

All storage repositories need new methods to support counting with filters.

#### 7.4.1 CACertificatesRepo Interface

**File**: `core/pkg/engines/storage/ca.go`

| New Method | Signature | Description |
|------------|-----------|-------------|
| `CountWithFilters` | `(ctx, queryParams *QueryParameters) (int, error)` | Count CAs matching the provided filters |
| `CountByEngineWithFilters` | `(ctx, engineID string, queryParams *QueryParameters) (int, error)` | Count CAs in a specific engine, with additional filters |

#### 7.4.2 CertificatesRepo Interface

**File**: `core/pkg/engines/storage/ca.go`

| New Method | Signature | Description |
|------------|-----------|-------------|
| `CountWithFilters` | `(ctx, queryParams *QueryParameters) (int, error)` | Count certificates matching the provided filters |
| `CountByCAIDWithFilters` | `(ctx, caID string, queryParams *QueryParameters) (int, error)` | Count certificates for a CA, with additional filters |

#### 7.4.3 DMSRepo Interface

**File**: `core/pkg/engines/storage/dms.go`

| New Method | Signature | Description |
|------------|-----------|-------------|
| `CountWithFilters` | `(ctx, queryParams *QueryParameters) (int, error)` | Count DMS instances matching the provided filters |

#### 7.4.4 KeysRepo Interface

**File**: `core/pkg/engines/storage/kms.go`

| New Method | Signature | Description |
|------------|-----------|-------------|
| `CountWithFilters` | `(ctx, queryParams *QueryParameters) (int, error)` | Count keys matching the provided filters |
| `CountByEngineWithFilters` | `(ctx, engineID string, queryParams *QueryParameters) (int, error)` | Count keys in a specific engine, with additional filters |

#### 7.4.5 PostgreSQL Implementation

**File**: `engines/storage/postgres/*.go`

For each new interface method, implement in the PostgreSQL storage layer:
1. Start a GORM query on the appropriate model.
2. If `queryParams` is not nil, apply filters using the existing `ApplyFilters()` helper function with the appropriate filterable fields map.
3. Add any additional fixed conditions (e.g., `engine_id = ?` for engine-specific counts).
4. Execute `Count()` and return the result.

**Expected Behavior for Storage Methods**:

1. **`CountWithFilters(ctx, queryParams)` when queryParams is nil**: Execute a simple `SELECT COUNT(*) FROM table` with no WHERE clause. Return the total row count.

2. **`CountWithFilters(ctx, queryParams)` when queryParams has filters**: Parse the filter expression and translate each condition to SQL. For string equality (`field[eq]value`), generate `WHERE field = 'value'`. For contains (`field[contains]value`), generate `WHERE field LIKE '%value%'`. For JSONPath (`metadata[jsonpath]$.key == "value"`), generate the appropriate PostgreSQL JSONB query. Combine multiple conditions with AND. Execute the count query and return the result.

3. **`CountByEngineWithFilters(ctx, engineID, queryParams)`**: Start with a base condition `WHERE engine_id = ?`. If queryParams is not nil, AND with the translated filter conditions. Execute count and return. This ensures that even with filters, only resources belonging to the specified engine are counted.

4. **`CountByCAIDWithFilters(ctx, caID, queryParams)` (certificates)**: Start with a base condition `WHERE ca_id = ?`. If queryParams is not nil, AND with the translated filter conditions. This allows counting certificates within a specific CA while applying additional filters.

5. **Invalid filter handling**: If a filter references a field not in the filterable fields map, return an error immediately. The storage layer should not attempt to query with unknown fields. The error message should indicate which field is invalid.

6. **Empty result behavior**: If no rows match the filter conditions, return 0 (not an error). Zero is a valid count result.

### 7.5 OpenAPI Specification Updates

#### 7.5.1 Device Manager

**File**: `docs/device-manager-openapi.yaml`

No changes required—already includes filter parameter on `/stats` endpoint.

#### 7.5.2 CA Service

**File**: `docs/ca-openapi.yaml`

| Change | Description |
|--------|-------------|
| `/stats` endpoint | Add `ca_filter` and `cert_filter` query parameters with descriptions and examples. Add 400 response for invalid filters. Update description to explain dual-filter behavior. |
| `/stats/{id}` endpoint | Add `cert_filter` query parameter. Update description to explain certificate filtering within CA. |

#### 7.5.3 DMS Manager

**File**: `docs/dms-manager-openapi.yaml`

| Change | Description |
|--------|-------------|
| `/v1/stats` endpoint | Add `filter` query parameter reference. Add 400 response for invalid filters. Update description to explain filtering behavior. |

#### 7.5.4 KMS

**File**: `docs/kms-openapi.yaml`

| Change | Description |
|--------|-------------|
| New `/stats` endpoint | Add complete endpoint definition with `filter` parameter, `KeyStats` response schema, examples, and error responses. |
| New `KeyStats` schema | Define in components/schemas with `total`, `engine_distribution`, and `algorithm_distribution` properties. |

### 7.6 SDK Updates

#### 7.6.1 CA SDK

**File**: `sdk/ca.go`

| Change | Description |
|--------|-------------|
| Modify `GetStats` | Accept optional filter parameters and include them in the HTTP request query string. |
| Modify `GetStatsByCAID` | Accept optional certificate filter parameters. |

#### 7.6.2 DMS SDK

**File**: `sdk/dmsmanager.go`

| Change | Description |
|--------|-------------|
| Modify `GetDMSStats` | Accept optional `QueryParameters` and include in the HTTP request. |

#### 7.6.3 KMS SDK

**File**: `sdk/kms.go`

| Change | Description |
|--------|-------------|
| New method `GetKeyStats` | Add method to call `GET /v1/stats` with optional filter parameters. |

### 7.7 Middleware Updates

For each service, ensure the stats endpoint methods are properly wrapped by existing middleware (audit, event publishing, OpenTelemetry tracing) following the same patterns as other service methods.

## 8. Implementation Plan

This plan is designed for incremental implementation by a coding agent. Each step produces a testable increment. Steps within a phase can be executed sequentially. Each step includes verification criteria.

### Phase 1: Storage Layer Foundation

#### Step 1.1: Add CountWithFilters to CACertificatesRepo Interface

**Files to modify**: `core/pkg/engines/storage/ca.go`

**Changes**:
- Add method `CountWithFilters(ctx context.Context, queryParams *resources.QueryParameters) (int, error)` to `CACertificatesRepo` interface.

**Verification**: Code compiles. Run `go build ./...` from the `core` module. Expect compilation errors in PostgreSQL implementation (expected—will be fixed in Step 1.5).

#### Step 1.2: Add CountWithFilters to CertificatesRepo Interface

**Files to modify**: `core/pkg/engines/storage/ca.go`

**Changes**:
- Add method `CountWithFilters(ctx context.Context, queryParams *resources.QueryParameters) (int, error)` to `CertificatesRepo` interface.

**Verification**: Code compiles in `core` module. PostgreSQL implementation will fail to compile (expected).

#### Step 1.3: Add CountWithFilters to DMSRepo Interface

**Files to modify**: `core/pkg/engines/storage/dms.go`

**Changes**:
- Add method `CountWithFilters(ctx context.Context, queryParams *resources.QueryParameters) (int, error)` to `DMSRepo` interface.

**Verification**: Code compiles in `core` module.

#### Step 1.4: Add CountWithFilters to KeysRepo Interface

**Files to modify**: `core/pkg/engines/storage/kms.go`

**Changes**:
- Add method `CountWithFilters(ctx context.Context, queryParams *resources.QueryParameters) (int, error)` to `KeysRepo` interface.

**Verification**: Code compiles in `core` module.

#### Step 1.5: Implement CountWithFilters for CA Certificates in PostgreSQL

**Files to modify**: `engines/storage/postgres/ca_cert.go` (or equivalent CA storage file)

**Changes**:
- Implement `CountWithFilters` method for the CA certificates repository.
- If `queryParams` is nil, execute simple count query.
- If `queryParams` is not nil, apply filters using `ApplyFilters()` helper with `CAFilterableFields`, then count.

**Verification**: 
- Run `go build ./...` from `engines/storage/postgres` module—should compile.
- Write or run existing unit test that calls `CountWithFilters(ctx, nil)` and verifies it returns total count.
- Write or run unit test that calls `CountWithFilters(ctx, &QueryParameters{...})` with a simple filter and verifies correct count.

#### Step 1.6: Implement CountWithFilters for Certificates in PostgreSQL

**Files to modify**: `engines/storage/postgres/certificate.go` (or equivalent)

**Changes**:
- Implement `CountWithFilters` method for the certificates repository.
- Same logic as Step 1.5 but using `CertificateFilterableFields`.

**Verification**: 
- Compile succeeds.
- Unit test with nil params returns total certificate count.
- Unit test with filter returns filtered count.

#### Step 1.7: Implement CountWithFilters for DMS in PostgreSQL

**Files to modify**: `engines/storage/postgres/dms.go` (or equivalent)

**Changes**:
- Implement `CountWithFilters` method for the DMS repository.
- Use `DMSFilterableFields` for filter application.

**Verification**: 
- Compile succeeds.
- Unit tests pass for nil and filtered cases.

#### Step 1.8: Implement CountWithFilters for Keys in PostgreSQL

**Files to modify**: `engines/storage/postgres/kms.go` (or equivalent)

**Changes**:
- Implement `CountWithFilters` method for the keys repository.
- Use `KeyFilterableFields` for filter application.

**Verification**: 
- Compile succeeds.
- Unit tests pass for nil and filtered cases.

#### Step 1.9: Add CountByEngineWithFilters to CACertificatesRepo

**Files to modify**: 
- `core/pkg/engines/storage/ca.go` (interface)
- `engines/storage/postgres/ca_cert.go` (implementation)

**Changes**:
- Add method `CountByEngineWithFilters(ctx context.Context, engineID string, queryParams *resources.QueryParameters) (int, error)` to interface.
- Implement: add `WHERE engine_id = ?` condition, then apply queryParams filters if not nil.

**Verification**: 
- Compile succeeds.
- Unit test: create CAs in different engines, call method with specific engine ID, verify count matches only that engine's CAs.
- Unit test: add filter, verify count is further restricted.

#### Step 1.10: Add CountByEngineWithFilters to KeysRepo

**Files to modify**: 
- `core/pkg/engines/storage/kms.go` (interface)
- `engines/storage/postgres/kms.go` (implementation)

**Changes**:
- Add method `CountByEngineWithFilters(ctx context.Context, engineID string, queryParams *resources.QueryParameters) (int, error)` to interface.
- Implement with same pattern as Step 1.9.

**Verification**: 
- Compile succeeds.
- Unit tests verify engine-specific counting with and without additional filters.

#### Step 1.11: Add CountByCAIDWithFilters to CertificatesRepo

**Files to modify**: 
- `core/pkg/engines/storage/ca.go` (interface)
- `engines/storage/postgres/certificate.go` (implementation)

**Changes**:
- Add method `CountByCAIDWithFilters(ctx context.Context, caID string, queryParams *resources.QueryParameters) (int, error)` to interface.
- Implement: add `WHERE ca_id = ?` condition, then apply queryParams filters if not nil.

**Verification**: 
- Compile succeeds.
- Unit test: create certificates under different CAs, verify count matches specific CA.
- Unit test: add filter, verify count is further restricted.

**Phase 1 Complete Verification**: Run `go test ./...` in `engines/storage/postgres` module. All tests pass. Run `go build ./...` in workspace root—all modules compile.

**Note**: Comprehensive assembler-level tests will be added in subsequent phases to validate the storage layer integration end-to-end.

---

### Phase 2: DMS Manager Filtered Stats (Simplest Service)

#### Step 2.1: Add QueryParameters to GetDMSStatsInput

**Files to modify**: `core/pkg/services/dmsmanager.go`

**Changes**:
- Add field `QueryParameters *resources.QueryParameters` to `GetDMSStatsInput` struct.

**Verification**: Code compiles. Existing code passes nil implicitly (zero value is nil for pointer).

#### Step 2.2: Update DMS Service Implementation to Use Filters

**Files to modify**: `backend/pkg/services/dmsmanager.go`

**Changes**:
- In `GetDMSStats` method, replace call to `dmsStorage.Count()` with `dmsStorage.CountWithFilters(ctx, input.QueryParameters)`.

**Verification**: 
- Code compiles.
- Existing tests pass (they pass nil QueryParameters, which counts all).
- Write integration test: create 5 DMS instances with different names, call `GetDMSStats` with filter `name[contains]test`, verify count matches expected.

#### Step 2.3: Update DMS Controller to Parse Filter Parameters

**Files to modify**: `backend/pkg/controllers/dmsmanager.go`

**Changes**:
- In `GetDMSStats` handler, call `FilterQuery()` with `DMSFilterableFields` to parse query parameters.
- Pass parsed parameters to service in `GetDMSStatsInput`.

**Verification**: 
- Code compiles.
- Integration test via HTTP: `GET /v1/stats` returns total count (backward compatible).
- Integration test via HTTP: `GET /v1/stats?filter=name[contains]test` returns filtered count.
- Integration test: `GET /v1/stats?filter=invalid_field[eq]x` returns HTTP 400.

#### Step 2.4: Update DMS OpenAPI Specification

**Files to modify**: `docs/dms-manager-openapi.yaml`

**Changes**:
- Add `filter` query parameter to `/v1/stats` endpoint.
- Add HTTP 400 response for invalid filters.

**Verification**: Validate OpenAPI spec syntax (use `swagger-cli validate` or equivalent). Manual review of changes.

#### Step 2.5: Update DMS SDK

**Files to modify**: `sdk/dmsmanager.go`

**Changes**:
- Modify `GetDMSStats` function to accept optional `QueryParameters` parameter.
- Include filter in HTTP request query string when provided.

**Verification**: 
- Code compiles.
- Write SDK test: call `GetDMSStats` with nil params, verify success.
- Write SDK test: call `GetDMSStats` with filter params, verify correct query string generated.

**Phase 2 Complete Verification**: Run full integration test suite for DMS Manager. All tests pass. Filtered stats endpoint works end-to-end.

#### Phase 2 Testing Requirements

**Assembler Layer Tests** (`backend/pkg/assemblers/tests/dms-manager/filtered_stats_test.go`):

1. **Test end-to-end without filters**: Create DMSs, call stats endpoint, verify total count.
2. **Test name filtering**: Create DMSs with specific names, filter by name substring, verify count.
3. **Test metadata filtering**: Create DMSs with metadata, apply JSONPath filter, verify count.
4. **Test multiple filters**: Apply name + metadata filters, verify AND logic.
5. **Test zero results**: Apply non-matching filter, verify count = 0.
6. **Test via SDK**: Use HTTP SDK client to call stats endpoint with filters, verify correct results.

**Test File**: `backend/pkg/assemblers/tests/dms-manager/filtered_stats_test.go`

**Test Execution**: All DMS Manager assembler tests must pass. Manual verification via monolithic mode recommended.

---

### Phase 3: KMS Statistics Endpoint (New Endpoint)

#### Step 3.1: Add KeyFilterableFields

**Files to modify**: `core/pkg/resources/fields.go`

**Changes**:
- Add `KeyFilterableFields` map with entries: `key_id` (String), `name` (String), `engine_id` (String), `algorithm` (String), `size` (Number), `creation_ts` (Date), `tags` (StringArray), `metadata` (Json).

**Verification**: Code compiles. Fields map is exported and accessible.

#### Step 3.2: Add KeyStats Model

**Files to modify**: `core/pkg/models/kms.go`

**Changes**:
- Add new struct `KeyStats` with fields:
  - `TotalKeys int`
  - `KeysDistributionPerEngine map[string]int`
  - `KeysDistributionPerAlgorithm map[string]int`
- Add JSON tags for serialization.

**Verification**: Code compiles. Model can be instantiated and serialized to JSON.

#### Step 3.3: Add GetKeyStatsInput and Interface Method

**Files to modify**: `core/pkg/services/kms.go`

**Changes**:
- Add struct `GetKeyStatsInput` with field `QueryParameters *resources.QueryParameters`.
- Add method `GetKeyStats(ctx context.Context, input GetKeyStatsInput) (*models.KeyStats, error)` to `KMSService` interface.

**Verification**: Code compiles. Backend service implementation will fail to compile (expected—will be fixed in Step 3.4).

#### Step 3.4: Implement GetKeyStats in KMS Service

**Files to modify**: `backend/pkg/services/kms.go`

**Changes**:
- Implement `GetKeyStats` method:
  1. Call `keysStorage.CountWithFilters(ctx, input.QueryParameters)` for total.
  2. Iterate registered crypto engines, call `keysStorage.CountByEngineWithFilters(ctx, engineID, input.QueryParameters)` for each.
  3. For each algorithm (RSA, ECDSA, Ed25519), construct combined filter and count.
  4. On count errors, set value to -1 and log error.
  5. Return populated `KeyStats`.

**Verification**: 
- Code compiles.
- Unit test: mock storage, call `GetKeyStats` with nil params, verify all counts retrieved.
- Unit test: call with filter params, verify filter passed to storage.
- Unit test: simulate storage error for one engine, verify that engine has -1 count but others succeed.

#### Step 3.5: Add KMS Stats Controller Method

**Files to modify**: `backend/pkg/controllers/kms.go`

**Changes**:
- Add method `GetStats` that:
  1. Parses filter parameters using `FilterQuery()` with `KeyFilterableFields`.
  2. Calls `svc.GetKeyStats(ctx, GetKeyStatsInput{QueryParameters: params})`.
  3. Returns JSON response with `KeyStats`.

**Verification**: 
- Code compiles.
- Unit test: mock service, verify controller parses params and calls service.
- Unit test: invalid filter returns HTTP 400.

#### Step 3.6: Register KMS Stats Route

**Files to modify**: `backend/pkg/routes/kms.go`

**Changes**:
- Add route `rv1.GET("/stats", routes.GetStats)` before other routes.

**Verification**: 
- Code compiles.
- Integration test: `GET /v1/stats` returns `KeyStats` JSON.
- Integration test: `GET /v1/stats?filter=engine_id[eq]test` returns filtered stats.
- Integration test: `GET /v1/stats?filter=bad_field[eq]x` returns HTTP 400.

#### Step 3.7: Add KMS Stats Middleware Wiring

**Files to modify**: `backend/pkg/assemblers/kms.go`

**Changes**:
- Ensure `GetKeyStats` is wrapped by audit and event publishing middleware following existing patterns.

**Verification**: 
- Code compiles.
- Integration test: call stats endpoint, verify audit log entry created.

#### Step 3.8: Update KMS OpenAPI Specification

**Files to modify**: `docs/kms-openapi.yaml`

**Changes**:
- Add new endpoint `/stats` with GET method.
- Add `filter` query parameter.
- Add `KeyStats` schema in components/schemas.
- Add 200 and 400 responses.

**Verification**: Validate OpenAPI spec syntax. Manual review.

#### Step 3.9: Add KMS SDK GetKeyStats Method

**Files to modify**: `sdk/kms.go`

**Changes**:
- Add method `GetKeyStats(ctx context.Context, params *resources.QueryParameters) (*models.KeyStats, error)`.
- Make HTTP GET request to `/v1/stats` with optional filter query string.

**Verification**: 
- Code compiles.
- SDK test: call method, verify HTTP request made correctly.
- Integration test via SDK: verify end-to-end functionality.

**Phase 3 Complete Verification**: Run full integration test suite for KMS. Stats endpoint works end-to-end with filtering. All other KMS functionality unaffected.

#### Phase 3 Testing Requirements

**Assembler Layer Tests** (`backend/pkg/assemblers/tests/kms/stats_test.go`):

1. **Test end-to-end without filters**: Create keys across engines/algorithms, verify totals and distributions.
2. **Test engine filtering**: Filter by specific engine, verify distribution shows only that engine.
3. **Test algorithm filtering**: Filter by algorithm, verify distribution.
4. **Test metadata filtering**: Create keys with metadata, apply JSONPath filter, verify count.
5. **Test combined filters**: Apply multiple filters, verify AND logic.
6. **Test via SDK**: Use HTTP SDK to call stats endpoint, verify results.
7. **Test engine distribution**: Verify keys are counted per engine correctly with and without filters.
8. **Test algorithm distribution**: Verify keys are counted per algorithm correctly with and without filters.

**Test File**: `backend/pkg/assemblers/tests/kms/stats_test.go`

**Test Execution**: All KMS assembler tests pass. Stats endpoint accessible via monolithic mode. Verify no regressions in existing KMS functionality.

---

### Phase 4: CA Service Filtered Stats

#### Step 4.1: Add GetStatsInput Struct

**Files to modify**: `core/pkg/services/ca.go`

**Changes**:
- Add struct `GetStatsInput` with fields:
  - `CAQueryParameters *resources.QueryParameters`
  - `CertificateQueryParameters *resources.QueryParameters`

**Verification**: Code compiles.

#### Step 4.2: Modify GetStats Signature

**Files to modify**: `core/pkg/services/ca.go`

**Changes**:
- Change `GetStats(ctx context.Context) (*models.CAStats, error)` to `GetStats(ctx context.Context, input GetStatsInput) (*models.CAStats, error)`.

**Verification**: Code compiles in `core`. Backend implementation and all callers will fail to compile (expected).

#### Step 4.3: Update CA Service Implementation for GetStats

**Files to modify**: `backend/pkg/services/ca.go`

**Changes**:
- Update `GetStats` method signature to accept `GetStatsInput`.
- Add validation: if either `CAQueryParameters` or `CertificateQueryParameters` contains `status` filter, return `ErrValidateBadRequest`.
- Update CA counting logic to use `CountWithFilters` with `input.CAQueryParameters`.
- Update engine distribution to use `CountByEngineWithFilters` with `input.CAQueryParameters`.
- Update certificate counting to use `CountWithFilters` with `input.CertificateQueryParameters`.

**Verification**: 
- Code compiles.
- Unit test: call with nil params, verify same behavior as before.
- Unit test: call with CA filter, verify only CA counts affected.
- Unit test: call with certificate filter, verify only certificate counts affected.
- Unit test: call with status filter in CAQueryParameters, verify error returned.

#### Step 4.4: Update All GetStats Callers

**Files to modify**: 
- `backend/pkg/controllers/ca.go`
- `backend/pkg/middlewares/eventpub/ca.go` (if applicable)
- Any other files calling `GetStats`

**Changes**:
- Update all calls to `GetStats` to pass `GetStatsInput{}` (empty struct for backward compatibility initially).

**Verification**: 
- Full workspace compiles: `go build ./...` from workspace root.
- Existing tests pass—behavior unchanged when empty input provided.

#### Step 4.5: Update CA Controller to Parse Dual-Prefix Filters

**Files to modify**: `backend/pkg/controllers/ca.go`

**Changes**:
- In `GetStats` handler, parse `ca_filter` query parameters using `CAFilterableFields`.
- Parse `cert_filter` query parameters using `CertificateFilterableFields`.
- Pass both to service in `GetStatsInput`.

**Verification**: 
- Code compiles.
- Integration test: `GET /v1/stats` returns full stats (backward compatible).
- Integration test: `GET /v1/stats?ca_filter=engine_id[eq]test` returns CA-filtered stats.
- Integration test: `GET /v1/stats?cert_filter=serial_number[contains]ABC` returns cert-filtered stats.
- Integration test: `GET /v1/stats?ca_filter=...&cert_filter=...` applies both independently.
- Integration test: `GET /v1/stats?ca_filter=status[eq]ACTIVE` returns HTTP 400.

#### Step 4.6: Add CertificateQueryParameters to GetStatsByCAIDInput

**Files to modify**: `core/pkg/services/ca.go`

**Changes**:
- Add field `CertificateQueryParameters *resources.QueryParameters` to `GetStatsByCAIDInput` struct.

**Verification**: Code compiles.

#### Step 4.7: Update GetStatsByCAID Implementation

**Files to modify**: `backend/pkg/services/ca.go`

**Changes**:
- Update `GetStatsByCAID` to apply `CertificateQueryParameters` when counting certificates for the specified CA.
- Use `CountByCAIDWithFilters` instead of simple count.
- Add validation for status filter.

**Verification**: 
- Code compiles.
- Unit test: call with nil params, same behavior as before.
- Unit test: call with certificate filter, verify filtered count.
- Integration test: `GET /v1/stats/{id}?cert_filter=...` returns filtered stats for that CA.

#### Step 4.8: Update CA OpenAPI Specification

**Files to modify**: `docs/ca-openapi.yaml`

**Changes**:
- Add `ca_filter` and `cert_filter` query parameters to `/stats` endpoint.
- Add `cert_filter` query parameter to `/stats/{id}` endpoint.
- Add HTTP 400 response for invalid filters.
- Update descriptions.

**Verification**: Validate OpenAPI spec syntax. Manual review.

#### Step 4.9: Update CA SDK

**Files to modify**: `sdk/ca.go`

**Changes**:
- Modify `GetStats` to accept optional CA and certificate filter parameters.
- Modify `GetStatsByCAID` to accept optional certificate filter parameters.
- Include filters in HTTP request query strings.

**Verification**: 
- Code compiles.
- SDK tests verify correct query string generation.
- Integration tests via SDK verify end-to-end functionality.

**Phase 4 Complete Verification**: Run full integration test suite for CA Service. Filtered stats work for both endpoints. All other CA functionality unaffected. Backward compatibility maintained.

#### Phase 4 Testing Requirements

**Assembler Layer Tests** (`backend/pkg/assemblers/tests/ca/ca_stats_filtered_test.go`):

1. **Test global stats without filters**: Create CAs and certificates, verify totals and distributions.
2. **Test CA filtering by engine**: Create CAs across engines, filter by engine, verify counts.
3. **Test CA filtering by metadata**: Create CAs with metadata, apply JSONPath filter, verify.
4. **Test certificate filtering**: Create certificates with different properties, apply filters, verify counts.
5. **Test certificate filtering by metadata**: Apply JSONPath filter to certificates.
6. **Test dual filtering**: Apply CA filter + certificate filter, verify both applied independently.
7. **Test per-CA stats without filters**: Call GetStatsByCAID, verify certificate counts.
8. **Test per-CA stats with certificate filters**: Filter certificates within specific CA.
9. **Test via SDK**: Use HTTP SDK for both endpoints with various filters.
10. **Test status filter rejection**: Verify both endpoints reject status filters with HTTP 400.
11. **Test engine distribution**: Verify CA counts per engine with and without filters.
12. **Test status distribution**: Verify CA and certificate status distributions with filters.

**Test File**: `backend/pkg/assemblers/tests/ca/ca_stats_filtered_test.go`

**Test Execution**: All CA Service assembler tests pass. Both stats endpoints work with filters via monolithic mode. Verify backward compatibility by running existing CA tests without modification.

---

### Phase 5: Final Validation and Documentation

#### Step 5.1: Cross-Service Integration Tests

**Changes**:
- Write integration tests that verify consistent filter syntax across all services.
- Test that invalid field names return HTTP 400 with helpful error messages.
- Test that status filters are rejected on CA and Device Manager stats (where applicable).

**Verification**: All integration tests pass.

#### Step 5.2: Update Filtering Documentation

**Files to modify**: `docs/filtering.md`

**Changes**:
- Add section explaining filtered statistics endpoints.
- Document that status cannot be filtered (it's always computed as distribution).
- Add examples for each service's stats endpoint.

**Verification**: Manual review of documentation.

#### Step 5.3: Final Smoke Tests

**Changes**:
- Run monolithic mode: `go run ./monolithic/cmd/development/main.go`
- Manually test each stats endpoint with and without filters.
- Verify no regressions in other functionality.

**Verification**: All manual tests pass. No errors in logs.

**Implementation Complete**: All filtered statistics functionality implemented, tested, and documented.

#### Phase 5 Testing Requirements

**Cross-Service Validation**: Run assembler tests for all services to ensure consistency:

1. **Run DMS Manager tests**: `cd backend/pkg/assemblers/tests/dms-manager && go test -v -run TestGetDMSStatsFiltered`
2. **Run KMS tests**: `cd backend/pkg/assemblers/tests/kms && go test -v -run TestGetKeyStatsFiltered` (or equivalent)
3. **Run CA tests**: `cd backend/pkg/assemblers/tests/ca && go test -v -run TestCAStatsFiltered` (or equivalent)
4. **Run Device Manager tests**: Verify existing filtered stats tests still pass

**Regression Testing**:

1. **Run full test suite**: Execute `go test ./...` from workspace root
2. **Backward compatibility**: Verify all existing tests pass without modification
3. **Manual smoke test**: Start monolithic mode and verify each endpoint works

**Manual Testing Checklist**:

- [ ] Start monolithic mode: `go run ./monolithic/cmd/development/main.go`
- [ ] Test DMS Manager: `curl "http://localhost:8080/api/dmsmanager/v1/stats?filter=name[contains]test"`
- [ ] Test KMS: `curl "http://localhost:8080/api/kms/v1/stats?filter=engine_id[eq]golang"`
- [ ] Test CA Service: `curl "http://localhost:8080/api/ca/v1/stats?ca_filter=engine_id[eq]golang"`
- [ ] Test CA Service dual filter: `curl "http://localhost:8080/api/ca/v1/stats?ca_filter=...&cert_filter=..."`
- [ ] Verify invalid filter returns 400
- [ ] Verify status filter returns 400 (CA, Device Manager)
- [ ] Check logs for errors

**Phase 5 Complete Verification**: All assembler tests pass. All services behave consistently. Manual testing confirms functionality. No regressions detected.

---

### Dependency Graph

```
Phase 1 (Storage) ─┬─► Phase 2 (DMS) ─────────────────────────────────────►─┐
                   ├─► Phase 3 (KMS) ─────────────────────────────────────►─┤
                   └─► Phase 4 (CA) ──────────────────────────────────────►─┴─► Phase 5 (Validation)
```

Phases 2, 3, and 4 can be executed in parallel after Phase 1 completes. Phase 5 requires all prior phases.

## 9. Testing Strategy

### 9.1 Unit Tests

| Component | Test Focus |
|-----------|------------|
| Storage Layer | Test `CountWithFilters` with nil parameters, empty filters, single filter, multiple filters, and combined with fixed conditions. |
| Service Layer | Test filter validation (status filter rejection). Test correct filter propagation to storage. |
| Controller Layer | Test query parameter parsing. Test prefix-based filter separation (CA service). |

### 9.2 Integration Tests

| Test Category | Description |
|---------------|-------------|
| Backward Compatibility | Verify calls without filters return same results as before. |
| Filter Accuracy | Create test data, apply filters, verify counts match expected values. |
| Error Handling | Verify 400 response for status filters and invalid field names. |
| Edge Cases | Empty result sets, large filter expressions, JSONPath expressions. |

### 9.3 Test Cases Summary

| Test Case | Endpoint | Input | Expected Result |
|-----------|----------|-------|-----------------|
| No filters | `GET /stats` | None | Returns stats for all resources |
| Valid metadata filter | `GET /stats?filter=metadata[jsonpath]$.env == "prod"` | JSONPath filter | Returns stats for matching resources only |
| Status filter rejected | `GET /stats?filter=status[eq]ACTIVE` | Status filter | 400 Bad Request |
| Invalid field | `GET /stats?filter=invalid_field[eq]value` | Unknown field | 400 Bad Request |
| CA + Cert filters | `GET /stats?ca_filter=...&cert_filter=...` | Both filters | Returns stats with both filters applied independently |
| Empty result | `GET /stats?filter=name[eq]nonexistent` | Non-matching filter | Returns stats with zero counts |

## 10. Backward Compatibility

| Aspect | Guarantee |
|--------|-----------|
| API Calls | Existing calls without filter parameters continue to work unchanged |
| Response Format | Response schemas remain the same; no fields removed |
| Input Structs | Use pointer types (`*QueryParameters`) with nil meaning "no filter" |
| Storage Methods | Existing methods preserved; new methods added alongside |
| SDK | Existing method signatures preserved; new optional parameters added |

## 11. Security Considerations

| Consideration | Mitigation |
|---------------|------------|
| Authorization | Filtering is subject to the same authorization rules as list endpoints |
| Field Restrictions | Only fields in `FilterableFields` maps are allowed; unknown fields rejected |
| JSONPath Complexity | Complex expressions validated by existing filter parsing logic |
| DoS via Complex Queries | Same database query patterns as list endpoints; existing indexes apply |
| No New Attack Vectors | Filtering uses existing, audited code paths |

## 12. Risks and Mitigation

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Performance degradation with complex filters | Medium | Medium | Use database indexes; same query patterns as list endpoints |
| Breaking changes to API | Low | High | Use optional parameters with nil defaults; extensive testing |
| Inconsistent filter syntax across services | Medium | Low | Use shared `FilterQuery` helper; document standard syntax |
| Middleware compatibility issues | Low | Medium | Follow existing patterns; test all middleware layers |

## 13. Alternatives Considered

### 13.1 Separate Stats Endpoints for Filtered Queries

**Proposal**: Create new endpoints like `/stats/filtered` instead of adding parameters to existing endpoints.

**Decision**: Rejected

**Rationale**: Adds API surface area without benefit. Optional parameters are cleaner and maintain a single endpoint per resource type.

### 13.2 POST-based Stats with Body Filters

**Proposal**: Use POST requests with filter criteria in the request body for complex filter expressions.

**Decision**: Rejected

**Rationale**: Stats are read-only operations; GET is semantically correct. Query parameters match existing list endpoint patterns and enable caching.

### 13.3 GraphQL for Flexible Queries

**Proposal**: Implement GraphQL for complex statistical queries with flexible field selection and filtering.

**Decision**: Rejected

**Rationale**: Over-engineering for this use case. REST with filters is sufficient and consistent with existing API design. GraphQL would require significant infrastructure changes.

## 14. References

- [RFC-004: Dynamic Device Groups](RFC-004-DynamicDeviceGroups.md) - Uses filtered stats for group statistics
- [RFC-005: JSONPath Sorting](RFC005-jsonpath-sorting.md) - JSONPath expression support in queries
- [Device Manager OpenAPI](device-manager-openapi.yaml) - Reference implementation of filtered stats
- [KMS OpenAPI](kms-openapi.yaml) - KMS service API specification
- [Filtering Documentation](filtering.md) - Filter syntax reference

---

## 15. Implementation Summary (Phase 5 Completion)

**Date Completed:** 2026-01-30

### Implementation Status

All phases of RFC-008 have been successfully implemented:

- ✅ **Phase 1**: Storage layer foundation with `CountWithFilters` methods
- ✅ **Phase 2**: DMS Manager filtered stats endpoint
- ✅ **Phase 3**: KMS statistics endpoint with filtering
- ✅ **Phase 4**: CA Service filtered stats with dual-filter support
- ✅ **Phase 5**: Final validation, cross-service integration tests, and documentation

### Key Deliverables

#### 1. Cross-Service Integration Tests

A comprehensive test suite (`backend/pkg/assemblers/tests/cross_service_stats_test.go`) validates:
- Backward compatibility (no filters returns all resources)
- Invalid field name rejection with clear error messages
- Status filter rejection on CA and Device Manager stats
- Metadata JSONPath filter consistency across all services
- Filter syntax consistency (string, date, number operators)
- HTTP SDK integration for all services

#### 2. Enhanced Documentation

Updated [filtering.md](filtering.md) with a new "Filtered Statistics Endpoints" section covering:
- Overview and key characteristics
- Service-specific examples for CA, KMS, DMS Manager, and Device Manager
- Status filter restriction explanation
- SDK usage examples in Go
- Common use cases (compliance reporting, dashboard widgets, fleet analytics)
- Error handling reference

#### 3. API Consistency

All statistics endpoints now follow consistent patterns:
- Same filter syntax and operators across all services
- Consistent error messages for invalid filters
- Backward compatible (nil filters = global stats)
- Status distribution always computed (status field not filterable)

### Testing Coverage

**Unit Tests:** Individual service and storage layer tests verify filtering logic

**Integration Tests:** 
- Service-specific filtered stats tests:
  - `backend/pkg/assemblers/tests/ca/ca_stats_filtered_test.go`
  - `backend/pkg/assemblers/tests/kms/stats_test.go`
  - `backend/pkg/assemblers/tests/dms-manager/filtered_stats_test.go`
- Cross-service consistency tests:
  - `backend/pkg/assemblers/tests/cross_service_stats_test.go`

**HTTP SDK Tests:** End-to-end validation via HTTP clients for all services

### Verification

To verify the implementation:

```bash
# Run all filtered stats tests
cd backend/pkg/assemblers/tests
go test -v -run ".*Stats.*" ./...

# Run cross-service integration tests
go test -v -run TestCrossServiceFilteredStatsConsistency ./...

# Manual verification via monolithic mode
go run ./monolithic/cmd/development/main.go

# Test endpoints
curl "http://localhost:8080/api/ca/v1/stats?ca_filter=engine_id[eq]filesystem-1"
curl "http://localhost:8080/api/kms/v1/stats?filter=algorithm[ct]RSA"
curl "http://localhost:8080/api/dmsmanager/v1/stats?filter=name[ct]production"
curl "http://localhost:8080/api/devmanager/v1/stats?filter=tags[ct]production"
```

### Next Steps

This RFC is now fully implemented and ready for production use. Operators can leverage filtered statistics for:
- Dashboard widgets showing segmented resource counts
- Compliance reports for specific CA environments or certificate types
- Fleet analytics filtered by metadata properties
- Monitoring of specific crypto engines or key algorithms

All endpoints maintain backward compatibility with existing clients while enabling powerful new filtering capabilities.

