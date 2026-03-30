# Authorization Logging

The authorization engine now provides detailed logging that explains why each authorization decision is granted or rejected.

## Log Format

All authorization logs are prefixed with `[AUTHZ]` for easy filtering and searching.

### Log Symbols
- `✓` - Decision granted
- `✗` - Decision denied or error

## Log Levels

### 1. Request Initiation

When an authorization check begins:
```
[AUTHZ] ========== Authorization Request ==========
[AUTHZ] Principal: user-123
[AUTHZ] Action: read
[AUTHZ] Entity Type: device
[AUTHZ] Entity ID: device-456
[AUTHZ] ============================================
```

### 2. Policy Loading

Shows which policies are being loaded for the principal:
```
[AUTHZ] Loading policies for principal 'user-123'...
[AUTHZ] Found 2 policy/policies for principal
[AUTHZ]   Loading policy 1/2: policy-abc-123
[AUTHZ]   Policy 'Device Access Policy' loaded with 3 rule(s)
[AUTHZ]   Loading policy 2/2: policy-def-456
[AUTHZ]   Policy 'Admin Policy' loaded with 5 rule(s)
```

### 3. Authorization Check Type

#### Global Actions (create, list, etc.)
For actions that don't require database checks:
```
[AUTHZ] Checking global action: action=list, entityType=device
[AUTHZ] ✓ GRANTED: Global action 'list' on 'device' - matched policy rule
[AUTHZ]   Reason: Policy rule grants action 'list' on entity type 'device'
```

Or when denied:
```
[AUTHZ] Checking global action: action=create, entityType=organization
[AUTHZ] ✗ DENIED: Global action 'create' on 'organization'
[AUTHZ]   Reason: No policy rules grant this action (checked 8 total rules, 0 matched)
```

#### Atomic Actions (read, write, delete, control, etc.)
For actions that require checking specific entity access:
```
[AUTHZ] Checking atomic action: action=read, entityType=device, entityID=device-123
[AUTHZ]   Generating authorization filter...
[AUTHZ]   Filter generated: 5 condition(s), 6 join(s)
[AUTHZ]     Condition 1: iot_devices.device_id IN (?, ?)
[AUTHZ]     Condition 2: j0_0.id = ?
[AUTHZ]     Condition 3: j1_0.id = ?
[AUTHZ]     Condition 4: j2_0.id = ?
[AUTHZ]     Condition 5: iot_devices.device_id = ?
[AUTHZ]     Join 1: LEFT JOIN organizations AS j0_0 ON iot_devices.organization_id = j0_0.id
[AUTHZ]     Join 2: LEFT JOIN iot_gateways AS j0_1 ON j0_0.building_id = j0_1.id
[AUTHZ]     Join 3: LEFT JOIN iot_devices AS j0_2 ON j0_1.gateway_id = j0_2.device_id
[AUTHZ]     Join 4: LEFT JOIN buildings AS j1_0 ON iot_devices.building_id = j1_0.id
[AUTHZ]     Join 5: LEFT JOIN iot_devices AS j1_1 ON j1_0.gateway_id = j1_1.device_id
[AUTHZ]     Join 6: LEFT JOIN iot_gateways AS j2_0 ON iot_devices.gateway_id = j2_0.id
[AUTHZ]   Executing database query on table 'iot_devices'
[AUTHZ]   WHERE: iot_devices.device_id IN (?, ?) OR j0_0.id = ? OR j1_0.id = ? OR j2_0.id = ? OR iot_devices.device_id = ?
[AUTHZ]   Args: [device-1 device-4 org-1 building-1 gateway-1 device-123]
[AUTHZ]   Query result: found 1 matching record(s)
[AUTHZ] ✓ GRANTED: action=read, entityType=device, entityID=device-123
[AUTHZ]   Reason: Entity exists in database and matches at least one policy rule condition
```

### 4. No Access Paths
When no policies provide any access:
```
[AUTHZ] Checking atomic action: action=delete, entityType=device, entityID=device-999
[AUTHZ]   Generating authorization filter...
[AUTHZ]   Filter generated: 1 condition(s), 0 join(s)
[AUTHZ]     Condition 1: 1 = 0
[AUTHZ] ✗ DENIED: action=delete, entityType=device, entityID=device-999
[AUTHZ]   Reason: No access paths found - no policy grants provide access to this entity
```

### 5. Entity Not Found or No Access
When the database query returns no results:
```
[AUTHZ]   Query result: found 0 matching record(s)
[AUTHZ] ✗ DENIED: action=read, entityType=device, entityID=device-999
[AUTHZ]   Reason: Entity either doesn't exist or doesn't match any policy rule conditions
```

### 6. Final Decision
```
[AUTHZ] ========== Final Result: GRANTED ==========
```
or
```
[AUTHZ] ========== Final Result: DENIED ==========
```

## MatchAndAuthorize Logging

When using JWT token-based authentication:
```
[AUTHZ] ========== MatchAndAuthorize Request ==========
[AUTHZ] Action: control
[AUTHZ] Entity Type: device
[AUTHZ] Entity ID: device-123
[AUTHZ] Extracted Bearer token (length: 847)
[AUTHZ] Matching principals from authentication token...
[AUTHZ] Matched 2 principal(s): [principal-abc principal-def]
[AUTHZ] Loading policies for principal 'principal-abc'...
[AUTHZ] Found 1 policy/policies for principal 'principal-abc'
[AUTHZ] Policy 'User Device Access' loaded with 2 rule(s)
[AUTHZ] Loading policies for principal 'principal-def'...
[AUTHZ] Found 1 policy/policies for principal 'principal-def'
[AUTHZ] Policy 'Admin Access' loaded with 4 rule(s)
[AUTHZ] Checking authorization with combined policies...
[AUTHZ] ========== Final Result: GRANTED ==========
```

## Error Logging

Errors are clearly marked:
```
[AUTHZ] ✗ ERROR: Failed to get principal policies: connection timeout
[AUTHZ] ✗ ERROR: Failed to load policy abc-123: policy not found
[AUTHZ] ✗ ERROR: Authorization check failed: invalid entity type
```

## Filtering Logs

To view only authorization logs:
```bash
# In application logs
grep "\[AUTHZ\]" app.log

# In real-time
tail -f app.log | grep "\[AUTHZ\]"

# Only granted decisions
grep "\[AUTHZ\].*✓" app.log

# Only denied decisions
grep "\[AUTHZ\].*✗" app.log

# Only errors
grep "\[AUTHZ\].*ERROR" app.log
```

## Understanding Authorization Flow

1. **Request Received** - Shows what's being checked
2. **Policy Loading** - Shows which policies are evaluated
3. **Action Type Detection** - Identifies if it's global or atomic
4. **Filter Generation** - For atomic actions, shows SQL conditions
5. **Database Query** - Shows actual query execution and results
6. **Final Decision** - Clear grant or deny with reason

## Benefits

- **Debugging**: Quickly understand why access was denied
- **Auditing**: Track all authorization decisions
- **Security**: Verify policies are working as intended
- **Troubleshooting**: Identify configuration issues
- **Compliance**: Maintain detailed access logs
