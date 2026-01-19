# RFC: JSONPath Expressions in Sort Options

**Status:** Draft  
**Created:** 2026-01-19  
**Author:** Lamassu Development Team

---

## Abstract

This RFC proposes extending the sorting capabilities of the Lamassu API to support JSONPath expressions when sorting by JSON fields (e.g., `metadata`, `settings`). This enhancement enables sorting on deeply nested properties within JSON columns, complementing the existing JSONPath filtering support.

---

## Motivation

Currently, the Lamassu API supports:
- Sorting by top-level scalar fields (strings, numbers, dates, enums)
- Advanced filtering on JSON fields using JSONPath expressions

However, users cannot sort results by properties nested within JSON fields. Common use cases include:

1. **Sorting devices by metadata properties**: Sort devices by environment (`metadata.environment`), region (`metadata.region`), or priority (`metadata.priority`)
2. **Sorting DMS by settings values**: Order DMS instances by configuration parameters stored in `settings`
3. **Sorting certificates by custom metadata**: Organize certificates based on custom metadata like cost center, application name, or compliance level

**Example scenarios:**
- A user wants to list all devices sorted by the `environment` field in their metadata, grouping production devices together
- An administrator needs to view certificates ordered by the `priority` field in metadata to handle high-priority renewals first
- An operator wants to list DMSs sorted by their `max_devices` configuration value in settings

---

## Goals

1. **Extend sorting syntax** to support JSONPath expressions for JSON fields
2. **Maintain consistency** with existing JSONPath filtering implementation
3. **Preserve backward compatibility** with current sorting behavior
4. **Ensure database efficiency** by leveraging PostgreSQL's native JSONPath support
5. **Provide clear error handling** for invalid JSONPath expressions or missing fields

---

## Non-Goals

1. Multi-field sorting (sorting by multiple fields in priority order)
2. Custom sorting functions (e.g., natural sort, locale-specific collation)
3. Sorting by computed/aggregated values (e.g., array lengths, sums)
4. Client-side sorting optimizations

---

## Proposal

### API Design

#### HTTP Query Parameters

Extend the existing `sort_by` query parameter to accept JSONPath expressions with a special syntax:

```
?sort_by=<field>[jsonpath]<expression>
?sort_mode=asc|desc
```

**Examples:**

```http
# Sort devices by metadata.environment
GET /api/devmanager/v1/devices?sort_by=metadata[jsonpath]$.environment&sort_mode=asc

# Sort certificates by metadata.priority (numeric)
GET /api/ca/v1/cas/{id}/certificates?sort_by=metadata[jsonpath]$.priority&sort_mode=desc

# Sort DMS by settings.max_devices
GET /api/dmsmanager/v1/dms?sort_by=settings[jsonpath]$.max_devices&sort_mode=asc

# Sort by nested object property
GET /api/devmanager/v1/devices?sort_by=metadata[jsonpath]$.location.region&sort_mode=asc

# Sort by array element (first tag)
GET /api/devmanager/v1/devices?sort_by=metadata[jsonpath]$.tags[0]&sort_mode=asc
```

**URL-encoded format:**
```http
GET /api/devmanager/v1/devices?sort_by=metadata%5Bjsonpath%5D$.environment&sort_mode=asc
```

#### SDK Usage (Go)

Extend `resources.SortOptions` to support JSONPath expressions:

```go
// Current structure
type SortOptions struct {
    SortMode  SortMode
    SortField string
}

// Proposed enhancement (no breaking changes, adds new optional field)
type SortOptions struct {
    SortMode       SortMode
    SortField      string
    JsonPathExpr   string  // Optional: JSONPath expression for JSON fields
}
```

**Usage examples:**

```go
// Sort by metadata.environment
qp := &resources.QueryParameters{
    PageSize: 25,
    Sort: resources.SortOptions{
        SortMode:     resources.SortModeAsc,
        SortField:    "metadata",
        JsonPathExpr: "$.environment",
    },
}

// Sort by nested numeric value
qp := &resources.QueryParameters{
    Sort: resources.SortOptions{
        SortMode:     resources.SortModeDesc,
        SortField:    "metadata",
        JsonPathExpr: "$.priority",
    },
}

// Traditional sorting (backward compatible)
qp := &resources.QueryParameters{
    Sort: resources.SortOptions{
        SortMode:  resources.SortModeAsc,
        SortField: "status",
    },
}
```

---

### Implementation Details

#### 1. Query Parameter Parsing

Modify `backend/pkg/controllers/utils.go` in the `FilterQuery` function:

```go
case "sort_by":
    value := v[len(v)-1]
    sortQueryParam := value
    
    // Check for JSONPath syntax: field[jsonpath]expression
    if strings.Contains(sortQueryParam, "[jsonpath]") {
        parts := strings.SplitN(sortQueryParam, "[jsonpath]", 2)
        if len(parts) == 2 {
            field := strings.Trim(parts[0], " ")
            jsonPathExpr := strings.Trim(parts[1], " ")
            
            // Validate field exists and is JSON type
            fieldType, exists := filterFieldMap[field]
            if exists && fieldType == resources.JsonFilterFieldType {
                queryParams.Sort.SortField = field
                queryParams.Sort.JsonPathExpr = jsonPathExpr
            }
        }
    } else {
        // Traditional field sorting (existing code)
        sortField := strings.Trim(sortQueryParam, " ")
        _, exists := filterFieldMap[sortField]
        if exists {
            queryParams.Sort.SortField = sortField
        }
    }
```

#### 2. PostgreSQL Query Generation

Modify `engines/storage/postgres/utils.go` in the `ApplyPagination` function:

```go
if queryParams.Sort.SortField != "" {
    if queryParams.Sort.JsonPathExpr != "" {
        // JSONPath sorting
        // Use PostgreSQL's #>> operator to extract JSON value as text
        // Or #> for JSON value (better for numbers/booleans)
        sortColumn := fmt.Sprintf(
            "(%s #>> '%s')",
            queryParams.Sort.SortField,
            convertJsonPathToPostgresPath(queryParams.Sort.JsonPathExpr),
        )
        
        // Build ORDER BY clause
        orderClause := fmt.Sprintf("%s %s", sortColumn, sortMode)
        tx = tx.Order(orderClause)
        
        // Update bookmark
        nextBookmark = nextBookmark + fmt.Sprintf(
            "sortM:%s;sortB:%s;sortJP:%s;",
            sortMode,
            queryParams.Sort.SortField,
            base64.StdEncoding.EncodeToString([]byte(queryParams.Sort.JsonPathExpr)),
        )
    } else {
        // Traditional sorting (existing code)
        sortBy = strings.ReplaceAll(queryParams.Sort.SortField, ".", "_")
        nextBookmark = nextBookmark + fmt.Sprintf("sortM:%s;sortB:%s;", sortMode, sortBy)
        tx = tx.Order(sortBy + " " + sortMode)
    }
}
```

**Helper function for path conversion:**

```go
// convertJsonPathToPostgresPath converts $.foo.bar to {foo,bar}
func convertJsonPathToPostgresPath(jsonPath string) string {
    // Remove leading $. if present
    path := strings.TrimPrefix(jsonPath, "$.")
    path = strings.TrimPrefix(path, "$")
    
    // Handle array indices: $.tags[0] -> {tags,0}
    path = strings.ReplaceAll(path, "[", ",")
    path = strings.ReplaceAll(path, "]", "")
    
    // Split by dots and format for PostgreSQL
    parts := strings.Split(path, ".")
    return "{" + strings.Join(parts, ",") + "}"
}
```

**PostgreSQL operators:**
- `#>>`: Extract as text (good for strings, general purpose)
- `#>`: Extract as JSON (preserves type for numbers/booleans)
- For numeric sorting: Cast the result using `CAST(... AS numeric)`

**Type-aware sorting:**

```go
// For better numeric/boolean sorting, use type-specific extraction
sortColumn := fmt.Sprintf(
    "CASE WHEN jsonb_typeof(%s #> '%s') = 'number' THEN (%s #>> '%s')::numeric " +
    "ELSE NULL END",
    field, path, field, path,
)
```

#### 3. Bookmark Handling

Extend bookmark encoding/decoding to include JSONPath expressions:

```go
case "sortJP":
    jsonPathExpr, err := base64.StdEncoding.DecodeString(queryPart[1])
    if err != nil {
        return "", fmt.Errorf("not a valid bookmark")
    }
    queryParams.Sort.JsonPathExpr = string(jsonPathExpr)
```

#### 4. Validation

Add validation in controllers:

```go
func validateJsonPathSort(field string, jsonPath string, filterFieldMap map[string]resources.FilterFieldType) error {
    // Check field exists
    fieldType, exists := filterFieldMap[field]
    if !exists {
        return fmt.Errorf("field %s not found", field)
    }
    
    // Check field is JSON type
    if fieldType != resources.JsonFilterFieldType {
        return fmt.Errorf("field %s is not a JSON field", field)
    }
    
    // Basic JSONPath validation
    if !strings.HasPrefix(jsonPath, "$.") && !strings.HasPrefix(jsonPath, "$[") {
        return fmt.Errorf("invalid JSONPath expression: must start with $.")
    }
    
    return nil
}
```

---

### PostgreSQL Considerations

#### Index Support

For optimal performance, consider creating PostgreSQL GIN indexes on commonly sorted JSON paths:

```sql
-- Index for metadata.environment
CREATE INDEX idx_device_metadata_environment 
ON devices USING GIN ((metadata -> 'environment'));

-- Index for metadata.priority (numeric)
CREATE INDEX idx_certificate_metadata_priority 
ON certificates USING BTREE (((metadata ->> 'priority')::numeric));

-- General GIN index (supports multiple paths but slower)
CREATE INDEX idx_device_metadata_gin 
ON devices USING GIN (metadata jsonb_path_ops);
```

#### NULL Handling

When a JSONPath expression doesn't match (property doesn't exist), PostgreSQL returns NULL. These should be sorted according to the standard NULL sorting rules:

- `ASC`: NULLs last (default)
- `DESC`: NULLs first (default)

Can be customized with `NULLS FIRST` / `NULLS LAST`:

```sql
ORDER BY (metadata #>> '{environment}') ASC NULLS LAST
```

#### Type Coercion

For numeric and boolean sorting, explicit casting may be needed:

```sql
-- Numeric sorting
ORDER BY (metadata ->> 'priority')::numeric DESC

-- Boolean sorting
ORDER BY (metadata ->> 'enabled')::boolean ASC

-- Date sorting
ORDER BY (metadata ->> 'created_at')::timestamp DESC
```

---

## Security Considerations

1. **SQL Injection Prevention**: 
   - Never directly interpolate user input into SQL
   - Use parameterized queries or proper escaping
   - Validate JSONPath expressions against a strict pattern

2. **Resource Exhaustion**:
   - Complex JSONPath expressions might be expensive
   - Consider query timeouts
   - Monitor slow query logs

3. **Field Access Control**:
   - Ensure users can only sort by fields they have permission to read
   - Leverage existing filter field maps for authorization

4. **Denial of Service**:
   - Limit JSONPath expression length
   - Reject deeply nested paths (e.g., max depth of 5-10 levels)

**Validation regex:**
```go
const jsonPathPattern = `^\$(\.[a-zA-Z_][a-zA-Z0-9_]*|\[\d+\]){1,10}$`
```

---

## Testing Strategy

### Unit Tests

1. **JSONPath parsing**:
   - Valid expressions: `$.environment`, `$.location.region`, `$.tags[0]`
   - Invalid expressions: `environment`, `$.`, `$..`, `$[invalid]`

2. **PostgreSQL path conversion**:
   - `$.foo.bar` → `{foo,bar}`
   - `$.tags[0]` → `{tags,0}`
   - `$.nested.array[2].value` → `{nested,array,2,value}`

3. **Bookmark encoding/decoding** with JSONPath

### Integration Tests

1. **Sort devices by metadata.environment**:
   - Create devices with different environments (prod, staging, dev)
   - Verify ascending and descending order
   - Verify devices without environment field appear last/first

2. **Sort certificates by metadata.priority**:
   - Create certificates with numeric priority values
   - Verify numeric sorting (not lexicographic)
   - Test with missing priority fields

3. **Sort DMS by settings.max_devices**:
   - Create DMS instances with different max_devices values
   - Verify numeric sorting

4. **Pagination with JSONPath sorting**:
   - Ensure bookmarks work correctly
   - Verify consistent ordering across pages

5. **Combined filtering and JSONPath sorting**:
   - Filter by status and sort by metadata.priority
   - Verify correct interaction between filters and sorts

### Edge Cases

1. **Empty/null JSON fields**: Documents without the field
2. **Type mismatches**: Trying to numerically sort string values
3. **Array handling**: Sorting by non-existent array indices
4. **Deeply nested paths**: `$.a.b.c.d.e.f.g`
5. **Special characters in property names**: `$.metadata["property-with-dashes"]`
6. **Unicode characters in values**
7. **Very large JSON documents**

### Performance Tests

1. **Query performance** with and without indexes
2. **Impact on query planning** (EXPLAIN ANALYZE)
3. **Memory usage** with large result sets
4. **Comparison with traditional field sorting**

**Test data sets:**
- 1,000 documents with mixed metadata
- 10,000 documents with consistent metadata
- 100,000 documents (stress test)

---

## Migration Path

### Phase 1: Backend Implementation (Week 1-2)
1. Update `core/pkg/resources/query.go` (add `JsonPathExpr` field)
2. Implement parsing in `backend/pkg/controllers/utils.go`
3. Implement PostgreSQL query generation in `engines/storage/postgres/utils.go`
4. Add unit tests for parsing and conversion

### Phase 2: Testing & Validation (Week 2-3)
1. Integration tests for each resource type
2. Performance benchmarks
3. Security review and validation implementation
4. Edge case testing

### Phase 3: Documentation (Week 3)
1. Update existing `docs/filtering.md` with sorting examples
2. Add SDK examples for each language
3. Update API OpenAPI specifications
4. Create migration guide for API consumers

### Phase 4: Rollout (Week 4)
1. Alpha release with feature flag
2. Beta release to selected users
3. General availability
4. Monitor performance and gather feedback

---

## Backward Compatibility

This proposal is **fully backward compatible**:

1. **Existing sorting continues to work**: The traditional `sort_by=field` syntax remains unchanged
2. **Optional field**: `JsonPathExpr` is optional in `SortOptions`
3. **No API breaking changes**: New syntax uses existing query parameters
4. **Graceful degradation**: Invalid JSONPath expressions are ignored, falling back to no sorting or default behavior

**Version compatibility:**
- Clients using old SDK versions can still sort by traditional fields
- New SDK versions support both traditional and JSONPath sorting
- Server supports both syntaxes simultaneously

---

## Alternatives Considered

### 1. Separate Query Parameter

Use a new parameter like `sort_by_jsonpath`:

```http
?sort_by_jsonpath=metadata.environment&sort_mode=asc
```

**Pros:**
- Clearer separation between traditional and JSONPath sorting
- Easier parsing (no bracket syntax)

**Cons:**
- Inconsistent with filtering syntax (which uses `field[jsonpath]expression`)
- Requires documenting two different parameters
- More complex when combining with traditional sorting

### 2. Dot Notation Without Special Syntax

Allow direct dot notation for JSON fields:

```http
?sort_by=metadata.environment&sort_mode=asc
```

**Pros:**
- Simpler, more intuitive syntax
- No special characters needed

**Cons:**
- Ambiguous with existing nested field syntax (e.g., `subject.common_name`)
- No way to distinguish between table columns and JSON properties
- Harder to support advanced JSONPath features (arrays, filters)
- Different from filter syntax

### 3. Extended Sort Parameter with Mode

Combine field and mode in one parameter:

```http
?sort=metadata[jsonpath]$.environment:asc
```

**Pros:**
- Single parameter for all sorting options
- More compact

**Cons:**
- Breaking change (requires deprecating `sort_mode`)
- More complex parsing
- Inconsistent with current API design

### 4. GraphQL-style Sorting Object

Use a JSON object for complex sorting:

```http
?sort={"field":"metadata","jsonpath":"$.environment","mode":"asc"}
```

**Pros:**
- Very flexible for future extensions
- Supports multi-field sorting easily

**Cons:**
- Requires JSON parsing from query parameters
- More verbose for simple cases
- Encoding issues in URLs

**Decision:** We chose the `field[jsonpath]expression` syntax (option from the proposal) because:
- Consistency with existing filter syntax
- Backward compatible
- Familiar to users who already use JSONPath filtering
- No breaking changes required

---

## Open Questions

1. **Should we support multi-field sorting?**
   - Example: `?sort_by=status&sort_by=metadata[jsonpath]$.priority`
   - Priority order handling
   - Complexity vs. use case frequency

2. **Should we support JSONPath filter expressions in sorting?**
   - Example: `$.tags[*] ? (@ == "production")`
   - How to handle multiple matches (first, last, count)?

3. **Should we support aggregate functions?**
   - Example: `array_length($.tags)`
   - Additional complexity in PostgreSQL queries

4. **Custom NULL ordering?**
   - Should we expose `NULLS FIRST/LAST` to the API?
   - Default behavior might be sufficient

5. **Type hints?**
   - Should users specify expected type: `metadata[jsonpath:number]$.priority`?
   - Or auto-detect from JSON value type?

6. **Performance thresholds?**
   - What query timeout is acceptable?
   - When should we recommend creating indexes?

---

## Success Metrics

1. **Adoption**: 
   - % of API calls using JSONPath sorting within 3 months
   - Number of unique JSONPath expressions used

2. **Performance**:
   - p50, p95, p99 latency for queries with JSONPath sorting
   - No more than 10% performance degradation vs. traditional sorting

3. **Reliability**:
   - Error rate for JSONPath sort queries < 1%
   - Zero security incidents related to JSONPath injection

4. **User Satisfaction**:
   - Positive feedback from early adopters
   - Reduction in support tickets about sorting limitations

---

## References

- [PostgreSQL JSON Functions](https://www.postgresql.org/docs/current/functions-json.html)
- [PostgreSQL JSONPath](https://www.postgresql.org/docs/current/datatype-json.html#DATATYPE-JSONPATH)
- [Lamassu Filtering Documentation](./filtering.md)
- [JSONPath Specification (RFC 9535)](https://datatracker.ietf.org/doc/html/rfc9535)

---

## Appendix A: Complete Example

**Scenario:** Sort devices by environment priority (production first, then staging, then development), with devices missing environment at the end.

**HTTP Request:**
```http
GET /api/devmanager/v1/devices?sort_by=metadata[jsonpath]$.environment&sort_mode=asc&page_size=10
```

**SDK Code:**
```go
client := devicemanager.NewDeviceManagerClient(config)

resp, err := client.ListDevices(ctx, &resources.QueryParameters{
    PageSize: 10,
    Sort: resources.SortOptions{
        SortMode:     resources.SortModeAsc,
        SortField:    "metadata",
        JsonPathExpr: "$.environment",
    },
})

for _, device := range resp.Devices {
    env := device.Metadata["environment"]
    fmt.Printf("Device %s: environment=%v\n", device.ID, env)
}
```

**Generated SQL (simplified):**
```sql
SELECT * FROM devices
ORDER BY (metadata #>> '{environment}') ASC NULLS LAST
LIMIT 10;
```

**Result Order:**
1. Devices with `metadata.environment = "development"`
2. Devices with `metadata.environment = "production"`
3. Devices with `metadata.environment = "staging"`
4. Devices without `environment` in metadata (NULL)

---

## Appendix B: JSONPath Expression Examples

| Use Case | JSONPath | Description |
|----------|----------|-------------|
| Top-level property | `$.environment` | Extract environment field |
| Nested property | `$.location.region` | Extract region from location object |
| Array element | `$.tags[0]` | First element of tags array |
| Array last element | `$.tags[last]` | Last element of tags array |
| Deep nesting | `$.config.server.port` | Deeply nested numeric value |

**Unsupported (future consideration):**
- Filter expressions: `$.tags[?(@.priority > 5)]`
- Wildcards: `$.tags[*]`
- Multiple selections: `$.tags[0,3,5]`
- Recursive descent: `$..priority`

---

## Appendix C: Implementation Checklist

### Code Changes
- [ ] Update `core/pkg/resources/query.go` - add `JsonPathExpr` field
- [ ] Update `backend/pkg/controllers/utils.go` - parse JSONPath syntax
- [ ] Update `engines/storage/postgres/utils.go` - generate JSONPath ORDER BY
- [ ] Add `convertJsonPathToPostgresPath()` helper function
- [ ] Update bookmark encoding/decoding logic
- [ ] Add validation for JSONPath expressions
- [ ] Add unit tests for parsing logic
- [ ] Add unit tests for path conversion
- [ ] Add integration tests per resource type
- [ ] Add performance benchmarks

### Documentation
- [ ] Update `docs/filtering.md` with sorting section
- [ ] Add JSONPath sorting examples
- [ ] Update OpenAPI specs for all services
- [ ] Create SDK usage examples
- [ ] Update CHANGELOG.md
- [ ] Write blog post/announcement

### Testing
- [ ] Test with various JSONPath expressions
- [ ] Test NULL handling
- [ ] Test type coercion (numbers, booleans, dates)
- [ ] Test pagination consistency
- [ ] Test with filters + JSONPath sorting
- [ ] Performance testing with large datasets
- [ ] Security testing (injection attempts)

### Operations
- [ ] Create database indexes for common sort paths
- [ ] Set up monitoring for JSONPath query performance
- [ ] Document query optimization guidelines
- [ ] Create runbook for performance issues
- [ ] Plan rollback strategy

---

## Conclusion

This RFC proposes a natural extension to Lamassu's existing JSONPath filtering capabilities by enabling JSONPath expressions in sort operations. The design maintains consistency with current patterns, ensures backward compatibility, and leverages PostgreSQL's native JSON support for efficient implementation.

The proposal includes comprehensive implementation details, security considerations, testing strategy, and a clear migration path. By following this RFC, the Lamassu API will provide users with powerful and intuitive sorting capabilities for JSON fields, enhancing the overall developer experience.

**Next Steps:**
1. Review and gather feedback from stakeholders
2. Create proof-of-concept implementation
3. Validate performance characteristics
4. Finalize implementation plan and timeline
