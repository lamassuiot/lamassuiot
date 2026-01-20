# JSON Patch support (RFC 6902) ✅

## Overview

The API supports JSON Patch-style updates for mutable JSON fields (e.g., `metadata`, `settings`) following [RFC 6902](https://datatracker.ietf.org/doc/html/rfc6902) semantics. While some endpoints may also respond to `PUT`, the `PATCH` method is the preferred way to perform partial updates to these fields without overwriting the entire object.

Supported operations:
- **`add`**: Adds a value to an object or inserts it into an array.
- **`remove`**: Removes a value from an object or array.
- **`replace`**: Replaces an existing value.

---

## Request format

- **HTTP Method**: `PATCH` (or `PUT` on legacy/compatibility endpoints)
- **Content-Type**: `application/json`
- **Payload**: A JSON object containing a `patches` array of operations.

```json
{
  "patches": [
    { "op": "add", "path": "/owner", "value": "team-a" },
    { "op": "replace", "path": "/settings/timeout", "value": 30 },
    { "op": "remove", "path": "/deprecated_field" }
  ]
}
```

### Common metadata endpoints
| Service | Endpoint | Description |
|---|---|---|
| **CA** | `PATCH /api/ca/v1/cas/{id}/metadata` | Update CA metadata |
| **KMS** | `PATCH /api/kms/v1/keys/{id}/metadata` | Update key metadata |
| **Device** | `PATCH /api/devmanager/v1/devices/{id}/metadata` | Update device metadata |
| **DMS** | `PATCH /api/dmsmanager/v1/dms/{id}/metadata` | Patch DMS metadata |

---

## JSON Pointer (RFC 6901)

Paths used in the `path` property must follow [RFC 6901](https://datatracker.ietf.org/doc/html/rfc6901) syntax:

- **Root level**: `/field`
- **Nested objects**: `/parent/child`
- **Array elements**: `/items/0`, `/items/1`
- **Append to array**: `/items/-` (special character meaning "after the last element")
- **Escaping**: `/` must be escaped as `~1`, and `~` must be escaped as `~0`.
  - Example: A key named `lamassu/io` would be referenced as `/lamassu~1io`.

---

## Enhanced Behavior: Automatic Parent Creation

Standard JSON Patch requires the parent path to exist before adding a child element. To simplify client integrations, Lamassu IoT includes **automatic parent creation** for adding elements to arrays and objects within metadata fields.

- **Arrays**: If you add to index `0` or use `-` on a non-existing array path, the server will automatically initialize an empty array before applying the patch.
- **Objects**: Adding a value to a nested path will create any missing intermediate objects.

**Example**:
If `metadata` is `{}` and you send:
`{"op": "add", "path": "/lamassu.io/kms/binded-resources/0", "value": {"id": "123"}}`

The server will automatically create the `lamassu.io/kms` object and the `binded-resources` array.

---

## SDK Usage (Go)

The Lamassu SDK provides a `PatchBuilder` to construct these operations safely.

```go
import (
    "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
    "github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
)

// Initialize the builder
pb := helpers.NewPatchBuilder()

// Build operations using JSONPointerBuilder for proper escaping
pb.Add(helpers.JSONPointerBuilder("owner"), "admin")
pb.Replace(helpers.JSONPointerBuilder("settings", "retries"), 5)
pb.Remove(helpers.JSONPointerBuilder("old_config"))

// Get the patch slice
patches := pb.Build() // []models.PatchOperation

// Use in SDK client call
err := client.UpdateCAMetadata(ctx, caID, patches)
```

---

## Behavior & validation rules

- **Non-null values**: `add` and `replace` operations require a `value`. Sending `null` as a value will result in a validation error.
- **Idempotent Removal**: Removing a path that does not exist is treated as a success (no-op) rather than an error.
- **Atomic Operations**: All patches in the `patches` array are applied atomically. If one fails, the entire update is rolled back.
- **Size Limits**: Metadata fields have a maximum size defined by the underlying storage (PostgreSQL JSONB), typically large enough for thousands of entries.

---

## Examples

### Append a tag to a device
```bash
curl -X PATCH "https://lamassu.io/api/devmanager/v1/devices/dev-123/metadata" \
  -H "Content-Type: application/json" \
  -d '{
    "patches": [
      { "op": "add", "path": "/tags/-", "value": "production" }
    ]
  }'
```

### Complex update (Multi-op)
```bash
curl -X PATCH "https://lamassu.io/api/kms/v1/keys/key-456/metadata" \
  -H "Content-Type: application/json" \
  -d '{
    "patches": [
      { "op": "replace", "path": "/status", "value": "active" },
      { "op": "add", "path": "/last_audit", "value": "2026-01-13" },
      { "op": "remove", "path": "/temp_data" }
    ]
  }'
```

---

## System-Reserved Metadata Keys 🔐

Certain metadata keys are used by Lamassu IoT's internal subsystems and should be modified with care. These often use the `lamassu.io/` prefix.

| Key prefix | Purpose |
|---|---|
| `lamassu.io/kms/` | Key management binding and resource tracking. |
| `lamassu.io/ra/` | Registration Authority and DMS enrollment tracking. |
| `lamassu.io/iot/` | Cloud connector metadata (e.g., AWS IoT registration info). |

---

## Error Handling

- **`400 Bad Request`**: Returned if the patch is malformed, references a non-existent path (outside of `remove` ops), or if a required `value` is missing for `add`/`replace`.
- **`404 Not Found`**: Returned if the resource (CA, Key, Device) being patched does not exist.
- **`500 Internal Server Error`**: Unexpected failures during database atomic updates.

---

## Best Practices 💡

1. **Use `JSONPointerBuilder`**: Always use the SDK's pointer builder when working in Go to ensure keys with dots, slashes, or tildes are escaped correctly.
2. **Favor `PATCH` over `PUT`**: Unless you intend to replace the *entire* metadata object, use `PATCH` to minimize conflict risk and reduce payload size.
3. **Array Appending**: Use the `/path/to/array/-` syntax to append to lists without needing to track the current array length client-side.
4. **Validation**: Validate your JSON structure client-side before sending patches to avoid partial success leading to unexpected states (though patches are atomic per request).

---

## Related Documentation
- [Filtering and JSONPath](./filtering.md) — For querying these same fields using advanced expressions.

---

## Where to look in the codebase 🔎

- **Models**: [core/pkg/models/patches.go](../core/pkg/models/patches.go)
- **Logic**: [core/pkg/helpers/jsonpatches.go](../core/pkg/helpers/jsonpatches.go)
- **Tests**: [core/pkg/helpers/jsonpatches_test.go](../core/pkg/helpers/jsonpatches_test.go)


