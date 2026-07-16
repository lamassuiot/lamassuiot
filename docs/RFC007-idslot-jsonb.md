# RFC: Convert Device IdentitySlot to JSONB and Enable Filtering

## Status
Proposed

## Abstract
This RFC proposes converting the `devices.identity_slot` database column from `text` to `jsonb` in the PostgreSQL schema. This change will enable efficient indexing and querying capabilities. Furthermore, it explicitly adds the `identity_slot` field to the allowed filtering options for the Device API, enabling clients to filter devices based on identity properties (e.g., status, active version) using JSONPath expressions.

## Motivation
Currently, the `identity_slot` field in the `devices` table is stored as a `text` column, serializing the JSON representation of the identity slot. This approach limits the database's ability to:
1.  Efficiently query devices based on specific fields within the identity structure (e.g., `identity_slot.status`).
2.  Index specific paths within the JSON document for performance.

Clients need the ability to filter devices based on their identity status (e.g., "Show me all devices with a REVOKED identity"). Without a native `jsonb` type and exposed filtering, this requires fetching all devices and filtering client-side, which is inefficient.

## Proposal

### Database Changes
1.  **Migration**: Create a new database migration for the `devicemanager` component.
2.  **Schema Change**: Alter the `devices` table to change the type of `identity_slot` from `text` to `jsonb`.
    ```sql
    ALTER TABLE devices
    ALTER COLUMN identity_slot TYPE jsonb
    USING identity_slot::jsonb;
    ```
    *Note: Data conversion logic (`USING`) is required to cast existing text data to jsonb.*

### Code Changes
1.  **Device Model**: The `Device` struct in `core/pkg/models/device.go` currently uses `gorm:"serializer:json"`. This tag should be compatible with `jsonb` columns (as verified with the `metadata` field migration). No changes to the struct tags are strictly necessary if GORM handles `jsonb` similarly to how it handles `serializer:json` for text, but verifying compatibility or updating to `type:jsonb` if needed is recommended.
2.  **Filtering Configuration**: Update `core/pkg/resources/fields.go` to include `identity` in the `DeviceFilterableFields` map.
    ```go
    var DeviceFilterableFields = map[string]FilterFieldType{
        "id":                 StringFilterFieldType,
        // ... existing fields
        "metadata":           JsonFilterFieldType,
        "identity_slot":      JsonFilterFieldType, // New addition
    }
    ```

### API Usage Example
Once implemented, clients can query the API using JSONPath filters on the `identity_slot` field:

*   **Filter by Status**:
    `GET /v1/devices?filter=identity_slot[jsonpath]$.status == "ACTIVE"`

*   **Filter by Active Version**:
    `GET /v1/devices?filter=identity_slot[jsonpath]$.active_version > 1`

## Implementation Steps
1.  Generate a new SQL migration file in `engines/storage/postgres/migrations/devicemanager/` (e.g., `<timestamp>_idslot_text_to_jsonb.sql`).
2.  Apply the migration to the local environment.
3.  Modify `core/pkg/resources/fields.go` to add the `identity_slot` field.
4.  Verify that existing tests pass and added new integration tests for filtering by identity.

## Risks and Mitigation
*   **Migration Downtime**: locking the table during type conversion on large datasets. Mitigation: usage of `CONCURRENTLY` is not supported for `ALTER COLUMN TYPE` directly in standard Postgres without table rewrite, but `jsonb` conversion is generally fast for reasonable dataset sizes. For very large tables, a multi-step migration (add column, backfill, swap) might be considered, but standard `ALTER` is likely sufficient for current scale.
*   **GORM Compatibility**: Ensure `gorm:"serializer:json"` reads/writes correctly to `jsonb`. If `metadata` is already working this way, this risk is low.
