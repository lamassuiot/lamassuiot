# RFC: Dynamic Device Groups

| Status | Proposed |
|:---|:---|
| **Date** | 2026-01-15 |
| **Authors** | Engineering Team |
| **Focus** | Device Manager, Grouping Logic, User Experience |

## 1. Abstract

This RFC proposes a design for **Dynamic Device Groups** within the `device-manager` service. This functionality allows users to define groups based on dynamic logical expressions (e.g., matching tags or device properties) rather than static assignment. Groups supports nesting, where child groups inherit the restrictions of their parents. The feature includes capabilities for listing group members and computing aggregate statistics for devices within a group.

## 2. Motivation

As IoT fleets grow, managing devices individually becomes impractical. Operators need to efficiently:
- **Organize** devices based on attributes like location, firmware version, or hardware type.
- **Monitor** specific subsets of the fleet (e.g., "Show me the status of all V1 devices in the 'warehouse' zone").
- **Automate** targeting for future features (e.g., "Deploy update to group 'Beta Testers'").

Static grouping (manually assigning a device to a group) requires constant maintenance. Dynamic grouping ensures that as soon as a device's attributes change (e.g., it is tagged with `site:madrid`), it automatically becomes a member of the relevant groups without manual intervention.

## 3. High-Level Design

### 3.1 Dynamic Membership via Expressions
Instead of a `group_id` foreign key on the Device table, a `DeviceGroup` entity will store a collection of **Filter Options** strictly adhering to the existing `resources.FilterOption` structure used in current APIs.
Membership is calculated at runtime (query-time) by applying these filters.

**Example Scenario:**
- **Group A ("Europe")**: Filter `Field=tags`, `Op=Contains`, `Value=region:eu`
- **Device 1**: `{ "tags": ["region:eu"] }` -> **Member of A**
- **Device 2**: `{ "tags": ["region:us"] }` -> **Not Member**

### 3.2 Nested Groups
Groups can be organized in a hierarchy. A child group effectively intersects its specific criteria with all of its ancestors' criteria.

**Example Hierarchy:**
1.  **Root Group ("All Sensors")**: `type == 'sensor'`
2.  **Child Group ("Active Sensors")** (Child of 1): `status == 'valid'`
    *   *Effective Criteria*: `type == 'sensor' AND status == 'valid'`
3.  **Grandchild Group ("High Temp Active Sensors")** (Child of 2): `[metadata.temp] > 50`
    *   *Effective Criteria*: `type == 'sensor' AND status == 'valid' AND [metadata.temp] > 50`

### 3.3 Statistics
The system will provide real-time aggregation for groups, allowing a dashboard to show:
- Totals (N devices in group).
- Breakdown by Status (e.g., 50 Active, 2 Revoked, 1 Unknown).

## 4. Implementation Details

### 4.1 Data Model (PostgreSQL)

We will introduce a new table `device_groups` in the `device-manager` database.

```sql
CREATE TABLE device_groups (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    parent_id UUID REFERENCES device_groups(id), -- Nullable for root groups
    
    -- Structure to define rules.
    -- Stores a serialized JSON array of resources.FilterOption.
    criteria JSONB NOT NULL DEFAULT '[]',
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Index for parent traversal
CREATE INDEX idx_device_groups_parent ON device_groups(parent_id);
```

#### Criteria JSON Schema
The criteria column will store an array of `FilterOption` objects, directly mapping to the `resources.QueryParameters.Filters` used in the system.

```json
[
  { "Field": "tags", "FilterOperation": 7, "Value": "location:madrid" }, 
  { "Field": "status", "FilterOperation": 12, "Value": "valid" }
]
```
*(Note: FilterOperation values correspond to the `resources.FilterOperation` enum integers)*

### 4.2 Query Resolution Strategy

The resolution uses the existing `GetDevices` logic which accepts `resources.QueryParameters`.

**Algorithm:**
1.  **Fetch Group & Ancestors**: Use Recursive CTE to fetch the target group and all its parents.
2.  **Compose Criteria**: Concatenate the `Filters` list from all groups in the path. This creates an implicit `AND` condition across all levels.
3.  **Execute**: Invoke `DeviceManagerService.GetDevices` (or the underlying repository method) passing the combined `Filters`. This reuses the existing, security-hardened `ApplyFilters` logic in the storage engine.
    *   No custom SQL transpilation is needed.
    *   Standard `DeviceFilterableFields` are automatically respected.
4.  **Execute (Stats)**: For statistics, invoke `DeviceManagerService.GetDevicesStats` with the same combined `Filters`.
5.  **Result**: The result is a standard list of devices or the statistics object.

### 4.3 Service Architecture (`device-manager`)

**Components:**
1.  **GroupService**: Handles CRUD for Group definitions.
    *   `CreateGroup`, `UpdateGroup`, `DeleteGroup`.
    *   Validates that criteria fields are valid `DeviceFilterableFields` keys.
    *   Prevents circular references in parent_id.
2.  **GroupMemberService**: Responsible for resolving devices.
    *   `GetDevicesByGroup(groupID, pagination)`: Resolves hierarchy and calls `GetDevices` with combined filters.
    *   `GetGroupStats(groupID)`: Resolves hierarchy and calls `GetDevicesStats` with combined filters.

### 4.4 API Specification

**Management APIs:**
- `POST /device-groups`: Create a new definition.
- `PUT /device-groups/:id`: Update definition/parent.
- `GET /device-groups`: List groups (tree view or list).
- `GET /device-groups/:id`: Get details.

**Membership APIs:**
- `GET /device-groups/:id/devices`:
  - Returns: List of Device objects.
  - Query Params: `limit`, `offset`, `sort`.
  
- `GET /device-groups/:id/stats`:
  - Returns:
    ```json
    {
      "total_devices": 150,
      "by_status": {
        "valid": 140,
        "revoked": 10
      }
    }
    ```

## 5. Security & Performance Considerations

- **Performance**: Deep nesting or complex JSONB queries on tags can be slow.
    - *Mitigation*: Encourage use of standard columns. Create GIN indexes on `tags` column in `devices` table.
- **Recursion Depth**: Limit nesting depth (e.g., max 5 levels) to prevent runaway queries.
- **Security**: Since the implementation reuses the existing `GetDevices` logic, it inherits the existing SQL injection protections and validation of `DeviceFilterableFields`.

## 6. Implementation Plan

This section provides a step-by-step implementation plan following the Lamassu IoT architecture patterns. Each step includes concrete deliverables and suggested agent prompts for guided implementation.

### 6.1 Phase 1: Core Domain & Storage

#### Step 1.1: Database Schema & Migration
**Deliverables:**
- Create migration file in `engines/storage/postgres/migrations/devicemanager/`
- Create migration test in `engines/storage/postgres/migrations_test/`

**Migration SQL:**
```sql
-- Up Migration: YYYYMMDDHHMMSS_create_device_groups.up.sql
CREATE TABLE device_groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    parent_id UUID REFERENCES device_groups(id) ON DELETE CASCADE,
    criteria JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_device_groups_parent ON device_groups(parent_id);
CREATE INDEX idx_device_groups_name ON device_groups(name);
```

**Agent Prompt:**
```
Create a Goose migration for the device-manager database to add the device_groups table.
Include fields: id (UUID, PK), name (TEXT, unique), description (TEXT, nullable), 
parent_id (UUID, self-referencing FK with CASCADE), criteria (JSONB, default '[]'),
created_at and updated_at timestamps.
Add indexes on parent_id and name.
Also create a migration test following the pattern MigrationTest_DeviceManager_TIMESTAMP_create_device_groups
that validates the table structure and constraints.
```

#### Step 1.2: Domain Models
**Deliverables:**
- Add `DeviceGroup` model to `core/pkg/models/device.go`

**Agent Prompt:**
```
In core/pkg/models/device.go, add a new DeviceGroup struct with the following fields:
- ID (string, primary key)
- Name (string)
- Description (string)
- ParentID (*string, nullable)
- Criteria ([]resources.FilterOption, serialized as JSON)
- CreatedAt (time.Time)
- UpdatedAt (time.Time)

Follow the existing model patterns in the file. Use GORM tags for JSON serialization where needed.
```

#### Step 1.3: Storage Repository Interface
**Deliverables:**
- Add `DeviceGroupsRepo` interface to `core/pkg/engines/storage/devicemanager.go`

**Agent Prompt:**
```
In core/pkg/engines/storage/devicemanager.go, add a DeviceGroupsRepo interface with these methods:
- Insert(ctx, *models.DeviceGroup) (*models.DeviceGroup, error)
- Update(ctx, id string, updateFunc) (*models.DeviceGroup, error)
- Delete(ctx, id string) error
- SelectByID(ctx, id string) (*models.DeviceGroup, bool, error)
- SelectAll(ctx, *resources.QueryParameters) (string, error)
- SelectAncestors(ctx, id string) ([]*models.DeviceGroup, error) // for hierarchy traversal

Follow the existing patterns for other repository interfaces in the file.
```

#### Step 1.4: Postgres Repository Implementation
**Deliverables:**
- Implement `DeviceGroupsRepo` in `engines/storage/postgres/devicemanager/` (new file `device_groups.go`)

**Agent Prompt:**
```
Create engines/storage/postgres/devicemanager/device_groups.go implementing the DeviceGroupsRepo interface.
Use the postgresDBQuerier[models.DeviceGroup] pattern as seen in other repository implementations.
For SelectAncestors, use a recursive CTE query to traverse the parent_id chain up to root groups.
Implement validation to prevent circular references in parent_id during Insert/Update.
Follow the existing patterns in engines/storage/postgres/devicemanager/ files.
```

### 6.2 Phase 2: Service Layer

#### Step 2.1: Service Interface Definition
**Deliverables:**
- Add group-related methods to `DeviceManagerService` in `core/pkg/services/devicemanager.go`
- Create input/output structs for new methods

**Agent Prompt:**
```
In core/pkg/services/devicemanager.go, extend the DeviceManagerService interface with:
- CreateDeviceGroup(ctx, CreateDeviceGroupInput) (*models.DeviceGroup, error)
- UpdateDeviceGroup(ctx, UpdateDeviceGroupInput) (*models.DeviceGroup, error)
- DeleteDeviceGroup(ctx, DeleteDeviceGroupInput) error
- GetDeviceGroupByID(ctx, GetDeviceGroupByIDInput) (*models.DeviceGroup, error)
- GetDeviceGroups(ctx, GetDeviceGroupsInput) (string, error)
- GetDevicesByGroup(ctx, GetDevicesByGroupInput) (string, error)
- GetDeviceGroupStats(ctx, GetDeviceGroupStatsInput) (*models.DevicesStats, error)

Define the corresponding input structs following the existing patterns (e.g., CreateDeviceInput).
Criteria field in CreateDeviceGroupInput should be []resources.FilterOption.
GetDevicesByGroupInput should embed resources.ListInput[models.Device].
```

#### Step 2.2: Service Implementation
**Deliverables:**
- Implement new methods in `backend/pkg/services/devicemanager.go`
- Add helper function to compose filters from group hierarchy

**Agent Prompt:**
```
In backend/pkg/services/devicemanager.go, implement the new DeviceGroup methods in DeviceManagerServiceBackend.

For CreateDeviceGroup/UpdateDeviceGroup:
1. Validate that all Criteria[].Field values are keys in resources.DeviceFilterableFields
2. Check for circular parent references
3. Use the DeviceGroupsRepo to persist

For GetDevicesByGroup:
1. Fetch group by ID
2. Call DeviceGroupsRepo.SelectAncestors to get parent chain
3. Compose a merged []FilterOption from all groups' criteria (concatenate, implicit AND)
4. Call the existing GetDevices method with the composed filters

For GetDeviceGroupStats:
1. Use the same hierarchy resolution as GetDevicesByGroup
2. Call the existing GetDevicesStats method with the composed filters

Follow the existing service implementation patterns in the file.
```

### 6.3 Phase 3: HTTP Layer

#### Step 3.1: Request/Response Resources
**Deliverables:**
- Add request/response structs to `core/pkg/resources/devreq.go` and `devresp.go`

**Agent Prompt:**
```
In core/pkg/resources/devreq.go, add:
- CreateDeviceGroupBody { Name, Description, ParentID, Criteria []FilterOption }
- UpdateDeviceGroupBody { Name, Description, ParentID, Criteria []FilterOption }

In core/pkg/resources/devresp.go, add:
- GetDeviceGroupsResponse embedding IterableList[models.DeviceGroup]

Follow the existing patterns for device request/response types.
```

#### Step 3.2: Controllers
**Deliverables:**
- Add controller methods to `backend/pkg/controllers/devmanager.go`

**Agent Prompt:**
```
In backend/pkg/controllers/devmanager.go (devManagerHttpRoutes struct), add methods:
- CreateDeviceGroup(ctx *gin.Context): bind CreateDeviceGroupBody, call service
- UpdateDeviceGroup(ctx *gin.Context): bind URI param :id + UpdateDeviceGroupBody
- DeleteDeviceGroup(ctx *gin.Context): bind URI param :id
- GetDeviceGroupByID(ctx *gin.Context): bind URI param :id
- GetAllDeviceGroups(ctx *gin.Context): use FilterQuery helper, call service
- GetDevicesByGroup(ctx *gin.Context): bind URI param :group_id, use FilterQuery for pagination/sorting
- GetDeviceGroupStats(ctx *gin.Context): bind URI param :group_id

Follow the error handling patterns used in existing methods (400 for validation, 404 for not found, 500 for others).
Use FilterQuery(ctx.Request, resources.DeviceFilterableFields) for query parameter parsing.
```

#### Step 3.3: Routes
**Deliverables:**
- Add routes to `backend/pkg/routes/devmanager.go`

**Agent Prompt:**
```
In backend/pkg/routes/devmanager.go, within the NewDeviceManagerHTTPLayer function, add route group:

deviceGroupsRoutes := v1.Group("/device-groups")
{
    deviceGroupsRoutes.POST("", routes.CreateDeviceGroup)
    deviceGroupsRoutes.GET("", routes.GetAllDeviceGroups)
    deviceGroupsRoutes.GET("/:id", routes.GetDeviceGroupByID)
    deviceGroupsRoutes.PUT("/:id", routes.UpdateDeviceGroup)
    deviceGroupsRoutes.DELETE("/:id", routes.DeleteDeviceGroup)
    deviceGroupsRoutes.GET("/:group_id/devices", routes.GetDevicesByGroup)
    deviceGroupsRoutes.GET("/:group_id/stats", routes.GetDeviceGroupStats)
}

Follow the existing route definition patterns in the file.
```

### 6.4 Phase 4: Assembly & Testing

#### Step 4.1: Update Assembler
**Deliverables:**
- Wire up DeviceGroupsRepo in `backend/pkg/assemblers/device-manager.go`

**Agent Prompt:**
```
In backend/pkg/assemblers/device-manager.go, within the deviceManagerHttpServiceBuilder function:
1. Instantiate DeviceGroupsRepo using the postgres storage adapter
2. Pass it to the DeviceManagerServiceBackend constructor (update constructor signature)
3. Ensure middleware wrapping (event publishing, audit) still applies to new methods

Follow the existing pattern for other repository instantiations in the assembler.
```

#### Step 4.2: Integration Tests
**Deliverables:**
- Add tests in `backend/pkg/services/` or `backend/pkg/assemblers/tests/`

**Agent Prompt:**
```
Create integration tests for device groups functionality:
1. Test creating a root group with criteria
2. Test creating nested groups and verifying hierarchy resolution
3. Test GetDevicesByGroup returns correct filtered devices
4. Test GetDeviceGroupStats returns accurate counts
5. Test circular parent reference validation
6. Test invalid FilterOption.Field validation

Use dockertest for Postgres container setup. Follow patterns in existing assembler tests.
```

### 6.5 Phase 5: Documentation

#### Step 5.1: OpenAPI Specification
**Deliverables:**
- Update `docs/device-manager-openapi.yaml` with new endpoints

**Agent Prompt:**
```
Add to docs/device-manager-openapi.yaml:
- /device-groups endpoints (POST, GET, GET /:id, PUT /:id, DELETE /:id)
- /device-groups/:group_id/devices endpoint
- /device-groups/:group_id/stats endpoint
- Schema definitions for DeviceGroup, CreateDeviceGroupBody, UpdateDeviceGroupBody
- Include examples showing FilterOption array structure in criteria field

Follow the existing OpenAPI 3.0 patterns in the file.
```

### 6.6 Dependencies & Validation

Before starting implementation, ensure:
- `go work sync` to synchronize workspace dependencies
- Review `resources.FilterOperation` enum values for criteria serialization
- Confirm GIN index support on JSONB columns for performance

### 6.7 Incremental Rollout

Implement in order:
1. **Week 1**: Phases 1-2 (Domain, Storage, Service)
2. **Week 2**: Phase 3 (HTTP Layer)
3. **Week 3**: Phases 4-5 (Testing, Documentation)

Each phase should be committable and testable independently.

## 7. Future Work
- **Group Actions**: Trigger jobs on all devices in a group (e.g., "Rotate Keys for Group X").
- **Cached Stats**: If real-time `COUNT(*)` becomes expensive, background jobs can pre-calculate stats for groups periodically.
- **Group Templates**: Pre-defined group patterns for common use cases.
- **Event Notifications**: Publish events when devices join/leave groups dynamically.
