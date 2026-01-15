# RFC: Multi-Tenancy Strategy for Lamassu IoT

| Status | Proposed |
|:---|:---|
| **Date** | 2026-01-14 |
| **Authors** | Architecture Team |
| **Focus** | Persistence Layer & Incremental Migration |

## 1. Abstract

This RFC proposes a strategy for introducing multi-tenancy support to the Lamassu IoT platform. The goal is to allow multiple isolated tenants to coexist within the same system deployment while sharing underlying infrastructure. The migration will be performed incrementally to maintain system stability, starting with the persistence layer.

## 2. Motivation

Lamassu IoT currently operates as a single-tenant system. To support SaaS delivery models or organizational isolation within large enterprises, we need to enforce logical data boundaries. Multi-tenancy will enable:
-   **Data Isolation**: Strict separation of resources (certificates, keys, devices) by tenant.
-   **Resource Efficiency**: Shared compute and storage infrastructure.
-   **Simplified Operations**: Unified management of multiple environments.

## 3. Incremental Strategy

We propose a phased approach to minimize risk. We will evolve the system step-by-step, ensuring functional parity at each stage.

*   **Phase 1: Persistence Layer & Default Tenant (Scope of this RFC)**
    *   Introduce `tenant_id` to the database schema.
    *   Migrate existing data to a "default" tenant.
    *   Hard-code the application to operate in "default" tenant context.
*   **Phase 2: Context Propagation**
    *   Introduce `TenantID` in the request context (via Middleware).
    *   Update service interfaces to propagate context to storage engines.
*   **Phase 3: Path-Based Multi-Tenancy**
    *   Expose new API endpoints with `/:tenant_id/` in the path.
    *   Bind path parameter to the Tenant Context.
*   **Phase 4: API & AuthN/AuthZ**
    *   Update Authentication mechanisms (JWT/mTLS) to extract Tenant ID.
    *   Enforce tenant isolation in business logic.
*   **Phase 5: Management & onboarding**
    *   APIs for creating/managing tenants.

---

## 4. Phase 1: Implementation Details

The first phase focuses entirely on the **Persistence Layer**. The objective is to prepare the database and ORM layer for multi-tenancy without changing the external behavior of the system.

### 4.1 Database Schema Changes

We will add a `tenant_id` column to all primary entity tables across all databases (CA, KMS, Device Manager, etc.).

**Migration Plan (Goose):**
For each microservice database (e.g., `ca_certificates`, `device_manager`), we will create a new migration file:

```sql
-- Up Migration
ALTER TABLE certificates ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE ca_certificates ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';
-- Repeat for all tables ...

-- Create an index to ensure performance and constraint uniqueness if needed (e.g. serial_number per tenant?)
-- For Phase 1, we might keep global uniqueness or introduce compound indexes later.
CREATE INDEX idx_certificates_tenant_id ON certificates(tenant_id);
```

*Note: The `DEFAULT 'default'` clause ensures that all existing rows are automatically assigned to the "default" tenant.*

### 4.2 Application Logic Adaptation

We need to modify the Go codebase to be "Tenant Aware" but fixed to the "default" tenant for now.

#### A. Domain Models (`core/pkg/models`)
All persistent structs will implement a `TenantAware` interface or simply include the field.

```go
type CACertificate struct {
    // ... existing fields ...
    TenantID string `json:"tenant_id" gorm:"default:default"`
}
```

#### B. Storage Engine (`engines/storage/postgres`)
We will modify the generic `postgresDBQuerier` and `TableQuery` helpers to enforce tenant isolation.

**Current State:**
```go
func (db *postgresDBQuerier[E]) SelectAll(...) {
    tx := db.Table(db.tableName)
    // ...
}
```

**New State:**
We will introduce a filtering mechanism. For Phase 1, this will be hardcoded.

```go
const DefaultTenantID = "default"

func (db *postgresDBQuerier[E]) baseQuery() *gorm.DB {
    return db.DB.Table(db.tableName).Where("tenant_id = ?", DefaultTenantID)
}

func (db *postgresDBQuerier[E]) SelectAll(...) {
    tx := db.baseQuery() // Automatically applies tenant filter
    // ...
}
```

By filtering at the base query level, we ensure that **impossible** for the application to accidentally access data from future tenants, even if we were to change the constant later.

#### C. Create/Insert Operations
When inserting new records, we must ensure the `TenantID` is set.

```go
func (db *postgresDBQuerier[E]) Insert(ctx context.Context, model *E) (*E, error) {
    // Reflection or Interface type assertion to set TenantID = "default"
    // before saving to GORM.
    setTenantID(model, DefaultTenantID) 
    result := db.DB.Create(model)
    return model, result.Error
}
```

### 4.3 Unique Constraints (Consideration)
Currently, some fields like `serial_number` or `name` might be unique globally. 
*   **Action**: In Phase 1, we will **not** change unique constraints to be composite (`tenant_id`, `field`). We will keep global uniqueness to minimize migration friction.
*   **Deferred**: Composite unique constraints will be addressed in Phase 4 when we actually enable multiple tenants.

### 4.4 Agent Prompt
> **Task**: Implement Phase 1 (Persistence Layer)
>
> 1.  **Migrations**: For all databases defined in `engines/storage/postgres/migrations/`, create a new Go-based migration (using goose) that adds `tenant_id TEXT NOT NULL DEFAULT 'default'` to all primary entity tables.
> 2.  **Models**: Update all domain models in `core/pkg/models` (e.g., `CACertificate`, `Device`, `Key`) to include `TenantID string`.
> 3.  **Storage Engine**: Modify `engines/storage/postgres/utils.go`:
>     *   Update `postgresDBQuerier` struct.
>     *   Inject `tenant_id = 'default'` in all `baseQuery` (Select) operations.
>     *   Inject `tenant_id = 'default'` in `Insert` operations.
> 4.  **Verification**: Run `backend/test/...` to ensure no regression.


## 5. Phase 2: Context Propagation

The objective of Phase 2 is to move from a hardcoded "default" tenant to a dynamic context-based approach, allowing the application to "know" which tenant is currently active for a given request.

### 5.1 Context Middleware
We will introduce a new middleware in `backend/pkg/middlewares/tenant.go`.

*   **Logic**:
    1.  Check for a specific header (e.g., `X-Lamassu-Tenant-ID`) - useful for testing and internal calls.
    2.  If not found, fallback to "default" (preserves backward compatibility during migration).
    3.  Inject the Tenant ID into the Go `context.Context`.

```go
// backend/pkg/middlewares/tenant.go
const TenantIDKey = contextKey("tenant_id")

func TenantMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        tid := c.GetHeader("X-Lamassu-Tenant-ID")
        if tid == "" {
            tid = "default"
        }
        
        ctx := context.WithValue(c.Request.Context(), TenantIDKey, tid)
        c.Request = c.Request.WithContext(ctx)
        c.Next() // Continue to business logic
    }
}
```

### 5.2 Storage Layer Dynamic Filter
We will update the `postgresDBQuerier` modified in Phase 1 to read from the context instead of the constant.

```go
func (db *postgresDBQuerier[E]) baseQuery(ctx context.Context) *gorm.DB {
    tid, ok := ctx.Value(TenantIDKey).(string)
    if !ok || tid == "" {
        // Log warning in debug
        tid = "default" 
    }
    return db.DB.Table(db.tableName).Where("tenant_id = ?", tid)
}
```

*   **Impact**: The system is now technically capable of multi-tenancy. If an administrator manually creates records with `tenant_id='tenant-b'` in the DB and sends a request with `X-Lamassu-Tenant-ID: tenant-b`, they will see isolated data.

### 5.3 Event Bus Propagation
The system relies heavily on asynchronous events (CloudEvents). We must ensure the `tenant_id` context is preserved across the event bus boundaries. To support scalable event routing, we will utilize the **CloudEvents Partitioning Extension**.

1.  **Event Publishing**:
    *   Modify `core/pkg/helpers/events.go:BuildCloudEvent` to check for `TenantID` in the context.
    *   If present, map it to the `partitionkey` extension: `event.SetExtension("partitionkey", tid)`.

2.  **Event Handling**:
    *   Modify `core/pkg/services/eventhandling/handler.go:HandleMessage`.
    *   After parsing the CloudEvent, extract the `partitionkey` extension.
    *   Inject it back into the `context.Context` (as `TenantID`) passed to the specific event handlers.
    *   This ensures that background jobs triggered by events (e.g. CRL generation) operate in the correct tenant context.

### 5.4 Background Jobs Impact
Background jobs like `CryptoMonitor` (checking certificate expiration) and `VACrlMonitor` (checking CRL validity) run autonomously with a background context.
*   **Problem**: `helpers.InitContext()` creates a context without a `tenant_id`. In Phase 2, this would resolve to "default" (or fail strict checks in Phase 4), causing the job to ignore all other tenants.
*   **Solution**: Update jobs to iterate over all active tenants.
    *   Since we lack a dedicated `tenants` table in this phase, the job will query distinct `tenant_id`s from the relevant table (e.g., `ca_certificates`).
    *   The job execution loop will become:
        ```go
        tenants := svc.getAllTenantIDs()
        for _, tid := range tenants {
            ctx := context.WithValue(baseCtx, TenantIDKey, tid)
            // perform scan for this tenant
        }
        ```

### 5.5 Agent Prompt
> **Task**: Implement Phase 2 (Context Propagation)
>
> 1.  **Middleware**: Create `backend/pkg/middlewares/tenant.go`. Implement `TenantMiddleware` that checks for header `X-Lamassu-Tenant-ID` and sets it in context. Default to "default".
> 2.  **Storage Update**: Modify `engines/storage/postgres/utils.go` to retrieve `tenant_id` from `context.Context` instead of using the hardcoded constant from Phase 1.
> 3.  **Event Bus**: 
>     *   Update `core/pkg/helpers/events.go` to set `partitionkey` extension (with tenant_id value) in `BuildCloudEvent`.
>     *   Update `core/pkg/services/eventhandling/handler.go` to extract `partitionkey` from event and put it into context as `TenantID`.
> 4.  **Jobs**: Update `backend/pkg/jobs/` (`CryptoMonitor`, `VACrlMonitor`) to discover all tenants (e.g. distinct query) and loop through them, setting the Tenant ID in the context for each iteration.
> 5.  **Service Context**: Ensure all service interfaces in `backend/pkg/services` are correctly passing `ctx` down to the repository layer.

---

## 6. Phase 3: Path-Based Multi-Tenancy

In this phase, we make multi-tenancy explicit in the API structure. We will introduce a parallel set of endpoints that include the `tenant_id` in the URL path.

### 6.1 API Pattern
We will adopt the convention `/v2/:tenant_id/...` for all tenant-scoped resources.
*   Legacy API: `POST /v1/cas` (Defaults to `default` tenant via headers)
*   New API: `POST /v2/:tenant_id/cas`

### 6.2 Endpoint Mappings
The following table illustrates how existing endpoints will be mapped to the new multi-tenant structure.

**CA Service**
| Operation | Legacy Path (`/v1/...`) | Multi-Tenant Path (`/v2/:tenant_id/...`) |
| :--- | :--- | :--- |
| List CAs | `GET /cas` | `GET /v2/:tenant_id/cas` |
| Create CA | `POST /cas` | `POST /v2/:tenant_id/cas` |
| Get CA | `GET /cas/:id` | `GET /v2/:tenant_id/cas/:id` |
| Sign Cert | `POST /cas/:id/certificates/sign` | `POST /v2/:tenant_id/cas/:id/certificates/sign` |
| List Certs | `GET /certificates` | `GET /v2/:tenant_id/certificates` |
| Get Profile| `GET /profiles/:id` | `GET /v2/:tenant_id/profiles/:id` |

**Device Manager**
| Operation | Legacy Path (`/v1/...`) | Multi-Tenant Path (`/v2/:tenant_id/...`) |
| :--- | :--- | :--- |
| List Devices | `GET /devices` | `GET /v2/:tenant_id/devices` |
| Register Device | `POST /devices` | `POST /v2/:tenant_id/devices` |
| Get Device | `GET /devices/:id` | `GET /v2/:tenant_id/devices/:id` |
| Device Stats | `GET /stats` | `GET /v2/:tenant_id/stats` |

**KMS Service**
| Operation | Legacy Path (`/v1/...`) | Multi-Tenant Path (`/v2/:tenant_id/...`) |
| :--- | :--- | :--- |
| List Keys | `GET /keys` | `GET /v2/:tenant_id/keys` |
| Create Key | `POST /keys` | `POST /v2/:tenant_id/keys` |
| Sign | `POST /sign` | `POST /v2/:tenant_id/sign` |

### 6.3 Router Configuration
We will use Gin's grouping capabilities to map the tenant ID to the context.

```go
func RegisterTenantRoutes(r *gin.Engine) {
    // Legacy support (Phase 1 & 2 style)
    v1 := r.Group("/v1")
    v1.Use(HeaderTenantMiddleware()) 
    
    // Explicit tenant routes
    tenantV2 := r.Group("/v2/:tenant_id") 
    tenantV2.Use(PathTenantMiddleware())
    
    // Register controllers for both groups reuse the same handler logic
    routes.RegisterCA(v1)
    routes.RegisterCA(tenantV2)
}
```


### 6.3 Path Middleware
This middleware extracts the `tenant_id` from the path and injects it into the context, taking precedence over headers.

```go
func PathTenantMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        tid := c.Param("tenant_id")
        // Basic validation of tenant ID format
        if tid == "" {
            c.AbortWithStatusJSON(400, gin.H{"error": "Tenant ID missing"})
            return
        }
        
        ctx := context.WithValue(c.Request.Context(), TenantIDKey, tid)
        c.Request = c.Request.WithContext(ctx)
        c.Next()
    }
}
```

### 6.4 Agent Prompt
> **Task**: Implement Phase 3 (Path-Based Routing)
>
> 1.  **Middleware**: Add `PathTenantMiddleware` in `backend/pkg/middlewares/tenant.go` which extracts `:tenant_id` from gin params.
> 2.  **Assemblers**: Refactor `backend/pkg/assemblers/*.go` (ca, kms, devmanager, etc.).
>     *   Keep existing `/v1` group with `HeaderTenantMiddleware`.
>     *   Create new `/v2` group that uses `PathTenantMiddleware`.
>     *   Register the same controllers for both groups.
> 3.  **Routes**: Ensure `backend/pkg/routes` functions accept the RouterGroup and don't assume a specific root path.

---

## 7. Phase 4: Authentication & Security

In this phase, we implement strict authorization. Instead of trusting the request context alone, we enforce that the user *can* access the requested tenant.

### 7.1 JWT-Based Authorization
We will update the authentication middleware to inspect the JWT Access Token.
*   **Claim Structure**: The token must include a custom claim listing authorized tenants for the user.
    ```json
    {
      "sub": "user-123",
      "https://lamassu.io/tenants": ["tenant-a", "tenant-b", "default"]
    }
    ```

### 7.2 Access Control Logic
The middleware will perform a verification step before allowing the request to proceed to the controller.

1.  **Extract Requested Tenant**: Identify the target tenant from the URL path (`/v2/:tenant_id/...`) or Header (Legacy fallback).
2.  **Verify Access**: Check if the requested tenant exists in the user's `https://lamassu.io/tenants` claim list.

```go
func TenantAuthZMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        // 1. Get Requested Tenant (already put in Context by Phase 2/3 middlewares)
        requestedTenant, exists := c.Get("tenant_id")
        if !exists {
             c.AbortWithStatusJSON(500, gin.H{"error": "Tenant context missing"})
             return
        }
        
        // 2. Get User Claims (extracted by Auth Middleware)
        userClaims := c.MustGet("claims").(jwt.MapClaims)
        allowedTenants := parseTenants(userClaims["https://lamassu.io/tenants"])
        
        // 3. Verify Access
        if !contains(allowedTenants, requestedTenant.(string)) {
             c.AbortWithStatusJSON(403, gin.H{
                 "error": "Forbidden", 
                 "message": fmt.Sprintf("You do not have access to tenant '%s'", requestedTenant),
             })
             return
        }
        
        c.Next()
    }
}
```

### 7.3 Unique Constraint Migration
With multiple tenants active, we may now need to revisit database constraints.
*   **Action**: Migrate `(serial_number)` unique index to `(tenant_id, serial_number)`. This allows two different tenants to issues certificates with the same serial number (if they have their own CAs).

### 7.4 Agent Prompt
> **Task**: Implement Phase 4 (Authorization)
>
> 1.  **JWT Parsing**: Update `backend/pkg/middlewares/auth` or wherever JWT parsing happens to extract the `https://lamassu.io/tenants` claim into the context.
> 2.  **AuthZ Middleware**: Implement `TenantAuthZMiddleware` that compares the `tenant_id` in context (from path/header) against the allowed list from JWT.
> 3.  **Enforcement**: Apply this new middleware to the `/v2` router group in `backend/pkg/assemblers`.

---

## 9. Phase 5: Tenant Management Service

In the final phase, we introduce a dedicated service to manage the lifecycle of tenants, moving away from ad-hoc tenant creation via unique constraints or distinct queries.

### 9.1 Tenant Manager Service (`/backend/cmd/tenant-manager`)
A new microservice responsible for:
*   **Tenant Registry**: storing metadata (name, status, technical contacts, quotas) for each tenant.
*   **Onboarding**: Automating the provisioning of initial resources (e.g., default CA, Key aliases) when a new tenant is created.
*   **Offboarding**: Handling cleanup/archival of tenant data.

### 9.2 Architecture Update
*   **Database**: A new `tenants` database or table (global scope).
*   **Integration**: Background jobs (from Phase 2) will now query this service (or shared DB) to get the authoritative list of active tenants, replacing the `SELECT DISTINCT tenant_id` workaround.

### 9.3 API Definition
Exposed under `/v2/sys/tenants`:
*   `POST /tenants`: Create new tenant.
*   `GET /tenants`: List all tenants.
*   `GET /tenants/:id`: Get details.
*   `PUT /tenants/:id/status`: Suspend/Activate.

### 9.4 Agent Prompt
> **Task**: Implement Phase 5 (Tenant Management)
>
> 1.  **Service**: Scaffold a new microservice `tenant-manager` in `backend/cmd` and `backend/pkg/services`.
> 2.  **Model**: Define `Tenant` model in `core/pkg/models`.
> 3.  **API**: Implement CRUD endpoints.
> 4.  **Integration**: Update `CryptoMonitor` and `VACrlMonitor` to fetch the tenant list from this new source of truth.

---

## 10. Verification Plan

1.  **Migration Test**: Run existing migration tests. Verify `tenant_id` column exists and is populated with "default".
2.  **Regression Test**: Run the full suite of integration tests (`backend/test/...`). The system should behave exactly as before.
3.  **Data Persistence**: Manually inspect the database after running the application to ensure new records have `tenant_id='default'`.

## 10. Verification Plan

1.  **Migration Test**: Run existing migration tests. Verify `tenant_id` column exists and is populated with "default".
2.  **Regression Test**: Run the full suite of integration tests (`backend/test/...`). The system should behave exactly as before.
3.  **Data Persistence**: Manually inspect the database after running the application to ensure new records have `tenant_id='default'`.

## 11. Rollback Strategy

Since we use `DEFAULT 'default'`, the column addition is non-destructive.
*   **Down Migration**: Drop the `tenant_id` column.
*   **Code Revert**: Revert git changes.

## 12. Next Steps

Once Phase 1 is merged and deployed:
1.  Start Phase 2: Create a `TenantContext` middleware.
2.  Replace the hardcoded `DefaultTenantID` in `postgresDBQuerier` with a value extracted from `context.Context`.
