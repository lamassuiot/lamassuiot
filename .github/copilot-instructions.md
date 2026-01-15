# Lamassu IoT - Copilot Instructions

Lamassu IoT is an IoT-first PKI (Public Key Infrastructure) designed for industrial scenarios. This is a Go-based microservices architecture with modular crypto engines, storage backends, and event systems.

## Project Architecture

### Core Services
- **CA Service** (`backend/cmd/ca/`): Certificate Authority management and certificate issuance
- **KMS Service** (`backend/cmd/kms/`): Key Management Service for cryptographic operations
- **Device Manager** (`backend/cmd/device-manager/`): IoT device lifecycle management  
- **DMS Manager** (`backend/cmd/dms-manager/`): Device Management System operations (enrollment, re-enrollment)
- **VA Service** (`backend/cmd/va/`): Validation Authority for OCSP/CRL
- **Alerts Service** (`backend/cmd/alerts/`): Event notifications and subscriptions

### Repository Structure
| Path | Purpose |
|------|---------|
| `backend/` | Core service implementations (cmd + pkg) |
| `core/` | Shared domain models, service interfaces, helpers |
| `engines/` | Pluggable adapters (crypto, storage, eventbus, filesystem) |
| `sdk/` | HTTP clients implementing service interfaces |
| `monolithic/` | All-in-one development mode |
| `connectors/` | Cloud integrations (AWS IoT) |
| `shared/` | Common libraries (HTTP, AWS helpers) |

### Key Patterns

**Go Workspace**: Uses `go.work` with 18+ modules. Always use `go work sync` and workspace-aware commands. Changes in one module (e.g., `core/`) affect dependents.

**Service Assembly Pattern**: Each service follows the assembler pattern in `backend/pkg/assemblers/`. Services are composed of:
- Storage repos (Postgres via `engines/storage/postgres`)
- Crypto engines (Software, PKCS11, AWS KMS, Vault)
- Event buses (AMQP/RabbitMQ, AWS EventBridge, in-memory)
- HTTP routers with middleware chains
- Background jobs (e.g., certificate monitoring)

Example assembler flow:
```go
// 1. Setup loggers with helpers.SetupLogger
// 2. Create storage instances
// 3. Build service with NewXService(builder)
// 4. Wrap with middleware (event publishing, audit)
// 5. Setup HTTP routes
// 6. Start background jobs if enabled
```

**Engine Abstraction**: Core interfaces in `core/pkg/engines/` define contracts:
- `storage.*Repo` - Database operations (CACertificatesRepo, CertificatesRepo, etc.)
- `cryptoengines.CryptoEngine` - Key operations, signing, verification
- `eventbus.EventBus` - Pub/sub messaging with CloudEvents

**Configuration**: Uses mapstructure in `backend/pkg/config/` and `core/pkg/config/`. Each service embeds core configs for storage, event bus, crypto engines.

## Development Workflows

### Quick Start - Monolithic Mode
```bash
# Run all services in one process (Docker required for deps)
go run ./monolithic/cmd/development/main.go

# With specific crypto engines
go run ./monolithic/cmd/development/main.go -cryptoengines="vault,pkcs11"

# With AWS IoT connector
go run ./monolithic/cmd/development/main.go -awsiot -awsiot-keyid=XXX -awsiot-keysecret=YYY

# Use in-memory eventbus (no RabbitMQ needed)
go run ./monolithic/cmd/development/main.go -inmemory-eventbus

# Available flags: -standard-docker-ports, -disable-monitor, -disable-eventbus, 
#                  -sqlite, -disable-ui, -use-aws-eventbus
```
Access at `http://localhost:8080` or `https://localhost:8443`

### Running Tests
```bash
# Run tests for specific module (workspace-aware)
cd backend && go test ./... -timeout 900s

# With coverage
go run gotest.tools/gotestsum@latest --format github-actions ./... -coverpkg=./... -coverprofile coverage.txt

# Migration tests (require Docker)
cd engines/storage/postgres && go test ./migrations_test/...
```

### Building Services
```bash
# Build specific service
go build -o ca backend/cmd/ca/main.go

# With version info (production pattern)
VERSION=v3.0.0 SHA1VER=$(git rev-parse HEAD) now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
go build -ldflags "-X main.version=$VERSION -X main.sha1ver=$SHA1VER -X main.buildTime=$now" -o ca backend/cmd/ca/main.go
```

## Code Conventions

### Layer Architecture (Top to Bottom)
1. **Routes** (`backend/pkg/routes/`) - Gin router groups and URL path definitions
   ```go
   rv1.POST("/cas", routes.CreateCA)
   ```
2. **Controllers** (`backend/pkg/controllers/`) - HTTP handlers, request/response serialization
   ```go
   func (r *caHttpRoutes) CreateCA(ctx *gin.Context) {
       var body resources.CreateCABody
       ctx.BindJSON(&body)
       result, err := r.svc.CreateCA(ctx, services.CreateCAInput{...})
       ctx.JSON(201, result)
   }
   ```
3. **Services** (`backend/pkg/services/`, interfaces in `core/pkg/services/`) - Business logic
   ```go
   type CAService interface {
       CreateCA(ctx context.Context, input CreateCAInput) (*models.CACertificate, error)
   }
   ```
4. **Storage** (`core/pkg/engines/storage/`, impl in `engines/storage/postgres/`) - Database operations
   ```go
   type CACertificatesRepo interface {
       Insert(ctx context.Context, ca *models.CACertificate) (*models.CACertificate, error)
   }
   ```

### Service Implementation Pattern
- Core domain models in `core/pkg/models/` (CACertificate, Device, Certificate)
- Service interfaces in `core/pkg/services/` define the contract
- Implementations in `backend/pkg/services/` use storage repos
- Input/output structs for complex parameters (e.g., `CreateCAInput`)
- Always use `context.Context` as first parameter
- Services have a `SetService()` method for middleware wrapping

### Middleware Pattern
Services wrapped via middleware pattern for cross-cutting concerns:
```go
// In assembler
svc = eventpub.NewCAEventBusPublisher(eventPublisher)(svc)
svc = auditpub.NewCAAuditEventBusPublisher(auditPublisher)(svc)

// Middleware implementation (backend/pkg/middlewares/)
type CAEventPublisher struct {
    Next       services.CAService
    eventMWPub ICloudEventPublisher
}
func (mw CAEventPublisher) CreateCA(ctx context.Context, input ...) (*models.CACertificate, error) {
    defer func() {
        if err == nil { mw.eventMWPub.PublishCloudEvent(ctx, output) }
    }()
    return mw.Next.CreateCA(ctx, input)
}
```

## Event-Driven Architecture

### Event Publishing
Events are published automatically via middleware after successful operations. Event types defined in `core/pkg/models/events.go`.

**Event Sources**: Service identifiers prevent infinite loops
- `service/ca` - CA operations
- `service/kms` - Key management
- `service/devmanager` - Device operations
- `service/ra` - DMS operations
- `service/alerts` - Alert subscriptions

**Event Types**: Follow `{resource}.{action}` pattern
- CA: `ca.create`, `ca.status.update`, `ca.sign.certificate`
- Certificate: `certificate.create`, `certificate.status.update`
- Device: `device.create`, `device.update`, `device.delete`

**CloudEvents Format**: All events use CloudEvents specification with type, source, subject, and data fields.

### Event Subscription Pattern
Event handlers in service assemblers use dispatch pattern:
```go
// Event handler setup (backend/pkg/handlers/)
eventHandlers := handlers.NewServiceEventHandler(logger, service)
subHandler := ceventbus.NewEventBusMessageHandler(
    "SERVICE-DEFAULT",
    []string{"ca.#", "certificate.#"},  // Wildcard routing keys
    subscriber,
    logger,
    *eventHandlers,
)
subHandler.RunAsync()

// Handler dispatch
DispatchMap: map[string]func(*event.Event) error{
    string(models.EventCreateCAKey): func(e *event.Event) error {
        ca, err := chelpers.GetEventBody[models.CACertificate](event)
        return service.ProcessCA(context.Background(), ca)
    },
}
```

## Database Patterns

### Migration Testing
Migration tests in `engines/storage/postgres/migrations_test/` validate schema changes:
- **Test Naming**: `MigrationTest_{DBNAME}_{TIMESTAMP}_{description}` (exact pattern required)
- **Database Setup**: Use `RunDB(t, logger, dbName)` helper for Docker Postgres
- **Apply Migrations**: Use `ApplyMigration(t, logger, con, dbName)` - auto-detects migration from test name
- **Test Data**: Focus assertions on test-created data using IDs to avoid cross-test contamination
- **Cleanup**: Defer cleanup from RunDB to ensure containers are removed

Example:
```go
func MigrationTest_CA_20250107164937_add_is_ca(t *testing.T, logger *logrus.Entry, con *gorm.DB) {
    ApplyMigration(t, logger, con, CADBName)
    
    // Insert test data with known ID
    con.Exec(`INSERT INTO ca_certificates (id, ...) VALUES('test-ca-id', ...)`)
    
    // Assert on specific test data only
    var result map[string]any
    tx := con.Raw("SELECT * FROM ca_certificates WHERE id = 'test-ca-id'").Scan(&result)
    assert.Equal(t, "test-ca-id", result["id"])
}
```

### Storage Repository Implementation
Repositories in `engines/storage/postgres/` implement interfaces from `core/pkg/engines/storage/`:
- Use GORM for ORM operations
- Paginated queries return JSON strings via `StorageListRequest[T]`
- Select methods return existence boolean + optional entity
- Always return full models, not partial updates

## HTTP Endpoint Implementation

### Implementation Steps
1. **Define Routes** (`backend/pkg/routes/{service}.go`)
   ```go
   rv1.POST("/cas", routes.CreateCA)
   rv1.GET("/cas/:id", routes.GetCAByID)
   ```

2. **Create Controller** (`backend/pkg/controllers/{service}.go`)
   ```go
   type caHttpRoutes struct { svc services.CAService }
   func (r *caHttpRoutes) CreateCA(ctx *gin.Context) {
       var body resources.CreateCABody
       if err := ctx.BindJSON(&body); err != nil { ... }
       result, err := r.svc.CreateCA(ctx, services.CreateCAInput{...})
       // Map errors to HTTP status codes
       ctx.JSON(201, result)
   }
   ```

3. **Define Service Interface** (`core/pkg/services/{service}.go`)
   ```go
   type CAService interface {
       CreateCA(ctx context.Context, input CreateCAInput) (*models.CACertificate, error)
   }
   ```

4. **Implement Business Logic** (`backend/pkg/services/{service}.go`)
   ```go
   func (svc *CAServiceBackend) CreateCA(ctx context.Context, input CreateCAInput) (*models.CACertificate, error) {
       // Validate input
       // Call storage repos
       // Return domain models
   }
   ```

5. **Wire in Assembler** (`backend/pkg/assemblers/{service}.go`)
   ```go
   httpEngine := routes.NewGinEngine(logger)
   httpGrp := httpEngine.Group("/")
   routes.NewCAHTTPLayer(httpGrp, svc)
   ```

## Testing Strategies

### Integration Tests
- Use `dockertest` for container lifecycle (Postgres, Vault, RabbitMQ)
- Test helpers in `engines/*/test/` packages
- Clean up resources in defer statements

### Service Tests
- Mock storage repos and external services
- Test middleware behavior separately
- Use `testify/assert` for assertions

## Debugging Tips

### Logs
Each component uses structured logging with `helpers.SetupLogger(level, service, component)`:
```go
lSvc := helpers.SetupLogger(conf.Logs.Level, "CA", "Service")
lStorage := helpers.SetupLogger(conf.Storage.LogLevel, "CA", "Storage")
```

### Monolithic Mode
Use `monolithic/cmd/development/main.go` for local development:
- Runs all services in single process
- Automatically starts Docker dependencies (Postgres, RabbitMQ, Vault, SoftHSM proxy)
- In-memory event bus option (`-inmemory-eventbus`) for faster iteration
- Hot-reloadable with `go run`

### Common Issues
- **Workspace errors**: Run `go work sync && go mod tidy -e ./...`
- **Migration test failures**: Ensure test function name matches pattern `MigrationTest_{DB}_{TIMESTAMP}_{desc}`
- **Event not firing**: Check middleware is applied in assembler and event bus is enabled
- **Test data conflicts**: Use unique IDs in migration tests, don't rely on clean DB state

## Container Deployment

### Dockerfile Pattern
Each service has a Dockerfile in `ci/` with multi-stage build:
```dockerfile
# Build stage: golang:1.24.3-bullseye with workspace context
COPY go.work go.work
COPY {all modules} ...
RUN go work vendor && go build -ldflags="-X main.version=..."

# Runtime stage: ubuntu:20.04 with non-root user (1000:1000)
USER lamassu
CMD ["/app/service"]
```

### Service-Specific Notes
- **CA Service**: Includes PKCS11 proxy and OpenSC for HSM
- **AWS Connector**: Includes ca-certificates for TLS
- **Monolithic**: Single container for dev/testing

## Anti-Patterns

- ❌ Don't bypass workspace - always use `go work` commands
- ❌ Don't hardcode crypto engine IDs - use configuration
- ❌ Don't test database state globally - focus on test-created data
- ❌ Don't use raw SQL without parameterization
- ❌ Don't import across modules outside workspace dependencies
- ❌ Don't make assumptions about event delivery order
- ❌ Don't return partial models from storage repos
