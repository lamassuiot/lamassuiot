# VA CRLSettings por ID de CA (PR 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Indexar la configuración de CRL del VA por ID de CA (`va.crl_settings`, modelo `CRLSettings`) en lugar de por SKI (`va.va_role`, `VARole`), manteniendo funcionando los CDP antiguos `/crl/<ski>`.

**Architecture:** La fila `crl_settings` (PK `ca_id`, `legacy_ski` único nullable, `status` `ACTIVE|ARCHIVED` en este PR) sustituye a `va_role`. Los handlers de eventos, `CalculateCRL`, el job y la API resuelven por `ca_id`. `GET /crl/<id>` resuelve primero `ca_id` y después `legacy_ski`. El repositorio solo expone métodos acotados (con CAS donde el spec lo pide).

**Tech Stack:** Go, GORM/Postgres, goose (migraciones SQL), gin, gocloud blob, testify, dockertest.

**Spec:** `docs/superpowers/specs/2026-11-11-va-crl-settings-by-ca-id-design.md` (§12, PR 1). Los PR 2 (ciclo de vida, FKs, `DeleteCA`) y PR 3 (endurecimiento) tendrán su propio plan cuando este esté integrado.

## Alcance de este plan (PR 1, spec §12)

Incluye: modelo, migración (§6), URLs/CDP/IDP (§7), renombrado API/SDK/OpenAPI/authz (§8, §8.1), enrutado por ID en handlers, repositorio acotado con CAS, `status` (`ACTIVE`; `ARCHIVED` para huérfanos), 409 en `PUT` si no está `ACTIVE`.

No incluye (PR 2): `FINAL`, CRL final, handlers de `ca.status.update`/`ca.delete`, reconciliación, `signer_engine_id`/`signer_key_id`, FK de clave, `CHECK` por estado, cambios en `DeleteCA`, `DELETE /v1/crl-settings/{ca-id}`.

### Decisiones de este plan que se apartan o precisan el spec (revisar)

1. **Se mantiene la FK del certificado firmante en PR 1** (`crl_settings_signer_cert_fk`, `ON DELETE NO ACTION ON UPDATE CASCADE`, columna nullable). El §12 dice "sin las dos FKs", pero hoy existe `va_role_signer_certificate_fk` (`RESTRICT`, #832); quitarla sería una regresión de protección. Se renombra y se conserva. La FK compuesta de clave y el `CHECK` por estado siguen siendo del PR 2.
2. **`signer_engine_id` y `signer_key_id` no se crean en PR 1.** Sin la FK compuesta serían copias que se desincronizan. Se añaden en PR 2 con su backfill.
3. **El backend genera siempre el ID de CA** (decisión del usuario, actualizada el 2026-11-12). `CreateCA` e `ImportCA` ignoran cualquier ID de entrada, sin 400, y generan UUIDv7. Los IDs existentes y los de reemisión se conservan. El campo `ID` se elimina de los inputs Go, cuerpos HTTP, SDK y OpenAPI; en JSON antiguo se ignora. Los eventos usan el ID devuelto.
3b. **`GET /crl/<id>` con `ARCHIVED`** sirve la última CRL publicada (spec §5). Los huérfanos migrados quedan `ARCHIVED`.
4. **No hay `POST` ni `DELETE /v1/crl-settings`** en PR 1 (el `DELETE` es PR 2: necesita `ARCHIVED` de verdad y la acción authz `delete`).

## Global Constraints

- Módulo único `github.com/lamassuiot/lamassuiot/v4`; sin `go.mod` anidados (AGENTS.md).
- Tests por directorio con `CGO_ENABLED=1` y Docker activo: `cd <dir> && go tool gotestsum --format testname ./... -timeout 300s`.
- Nunca hacer `git commit`/`amend`/`push` salvo petición explícita del usuario. Los pasos "Commit" de abajo **solo se ejecutan si el usuario lo pide**; si no, se dejan los cambios en el árbol de trabajo.
- Nombre de test de migración: `MigrationTest_{DB}_{TIMESTAMP}_{desc}`; para el esquema VA ya existe un estilo propio en `engines/storage/postgres/migrations_test/va_signer_fk_test.go` (`RunDB`, `postgres.NewMigrator`, `m.Goose.UpTo/ApplyVersion`, `RollbackMigration`); seguirlo.
- Orden de migración: `kms`, `ca`, `va`. La migración del VA puede leer `ca.certificates` y `ca.ca_certificates`.
- Valores exactos del spec: `status` ∈ {`ACTIVE`, `ARCHIVED`} en PR 1; `legacy_ski` único nullable; `ca_id` sintético de huérfanos `legacy-<ski>`; IDs nuevos: UUIDv7 generado siempre en el backend; ID de entrada ignorado; CDP nuevo `http://<dominio-va>/crl/<ca-id>`; ruta bucket `pki/va/crl/<ca-id>/<n>.crl` con fallback `pki/va/crl/<legacy_ski>/<n>.crl` para filas con `legacy_ski`; subject de eventos `crl/<ca-id>`; defaults `Validity` 7 días y `RefreshInterval` 6d23h, `RegenerateOnRevoke` true (valores actuales de `InitCRLRole`).
- Cambio de API incompatible: `/v1/roles/:ca-ski` se elimina sin compatibilidad (decidido por el usuario).
- Trabajo de seguridad (CRL/KMS/authz): ejecutar `anthropic-skills:stride-dread-threat-model` sobre el diseño y `security-review` sobre el diff final (AGENTS.md).

## Review Focus

1. **Dos CAs con el mismo SKI** (migración): una CA = una fila; si un rol casa con >1 CA la migración falla listando rol y CAs, sin migrar nada (T2).
2. **ID de CA que colisiona con el `legacy_ski` de otra fila**: imposible para IDs nuevos (UUIDv7 generado en el backend, con guiones); la migración falla si un ID existente ya colisiona (T2, T7).
3. **ID de CA con `/` o caracteres no seguros**: migración falla listando la CA; `CreateCA`/`ImportCA` ignoran cualquier ID recibido y generan UUIDv7; el CDP de IDs existentes usa `url.PathEscape` (T2, T5, T7).
4. **CRL huérfana** (rol sin CA): sigue sirviéndose en `/crl/<ski>` como `ARCHIVED` y no se regenera (T2, T4, T6).
5. **Actualización concurrente de la fila**: `CalculateCRL` y `PUT` no se pisan (CAS sobre la versión de la última CRL; `UpdateCRLSettings` solo toca columnas de configuración) (T3, T4).

---

## File Structure

| Archivo | Responsabilidad |
|---|---|
| `core/pkg/models/va.go` | `CRLSettings`, `CRLSettingsOptions` (editable), `LatestCRLMeta`, `CRLSettingsStatus` |
| `core/pkg/engines/storage/va.go` | `VARepo` → `CRLSettingsRepo` con métodos acotados |
| `engines/storage/postgres/vastore.go` | Implementación Postgres del repositorio |
| `engines/storage/postgres/migrations/va/20261111120000_crl_settings.sql` | Migración `va_role` → `crl_settings` |
| `core/pkg/services/crl.go`, `core/pkg/services/va.go` | Interfaces `CRLService`/`VAService` y sus inputs |
| `backend/pkg/services/crl.go` | Lógica del VA (init, calculate, get, update, resolución de ID) |
| `backend/pkg/services/handlers/va-handlers.go` | Handlers por ID de CA |
| `backend/pkg/jobs/va-crl-job.go` | Job sobre `CRLSettings` `ACTIVE` |
| `backend/pkg/x509engines/x509engine.go` | CDP por ID de CA |
| `backend/pkg/services/ca.go` | Genera UUIDv7 y pasa el ID de CA al engine |
| `backend/pkg/controllers/va.go`, `backend/pkg/routes/va.go` | Rutas `/crl/:id`, `/v1/crl-settings[/:ca-id]` |
| `backend/pkg/middlewares/{audit,eventpub,otel}/crl.go` | Renombres y subject `crl/<ca-id>` |
| `core/pkg/models/events.go`, `core/pkg/errs/va.go`, `core/pkg/resources/vareq.go` | Renombres de eventos/errores/recursos |
| `sdk/va.go`, `backend/pkg/specs/va-openapi.yaml` | SDK y OpenAPI |
| `connectors/authz/pki.json` (+ preloads) | Entidad `crl_settings` (PK `ca_id`) |
| `core/pkg/services/mock/crl_mock.go` | Mock regenerado/editado a mano |

Antes de cada tarea, localizar usos con `codegraph_explore` (no con grep).

---

### Task 1: Modelo `CRLSettings` y repositorio acotado

**Files:**
- Modify: `core/pkg/models/va.go`, `core/pkg/engines/storage/va.go`, `core/pkg/engines/storage/engine.go` (`GetVARoleStorage` → `GetCRLSettingsStorage`), `engines/storage/postgres/vastore.go`, `engines/storage/postgres/engine.go`, `core/pkg/engines/storage/engine_test.go`
- Test: `engines/storage/postgres/test/crl_settings_repo_test.go` (sustituye a `va_signer_fk_test.go` en ese directorio; migrar sus casos)

**Interfaces:**
- Produces (`core/pkg/models/va.go`):
  ```go
  type CRLSettingsStatus string
  const (CRLSettingsActive CRLSettingsStatus = "ACTIVE"; CRLSettingsArchived CRLSettingsStatus = "ARCHIVED")
  type CRLSettings struct {
      CAID      string            `json:"ca_id"      gorm:"column:ca_id"`
      LegacySKI *string           `json:"legacy_ski,omitempty" gorm:"column:legacy_ski"`
      Options   CRLSettingsOptions `json:"crl_options" gorm:"embedded"`
      Status    CRLSettingsStatus `json:"status"`
      LatestCRL LatestCRLMeta     `json:"latest_crl" gorm:"embedded;embeddedPrefix:latest_crl_"`
  }
  type CRLSettingsOptions struct {
      SignerSerialNumber string       `json:"signer_serial_number" gorm:"column:signer_serial_number" validate:"required"`
      Validity           TimeDuration `json:"validity" gorm:"serializer:text"`
      RefreshInterval    TimeDuration `json:"refresh_interval" gorm:"serializer:text"`
      RegenerateOnRevoke bool         `json:"regenerate_on_revoke"`
  }
  ```
  (`LatestCRLMeta` no cambia.) La columna `signer_serial_number` es nullable en BD; el `validate:"required"` solo aplica al `PUT`.
- Produces (`core/pkg/engines/storage/va.go`):
  ```go
  type CRLSettingsRepo interface {
      Insert(ctx context.Context, s *models.CRLSettings) (*models.CRLSettings, error)
      Get(ctx context.Context, caID string) (bool, *models.CRLSettings, error)
      GetByLegacySKI(ctx context.Context, ski string) (bool, *models.CRLSettings, error)
      GetAll(ctx context.Context, req StorageListRequest[models.CRLSettings]) (string, error)
      UpdateOptions(ctx context.Context, caID string, opts models.CRLSettingsOptions) (*models.CRLSettings, error)
      UpdateLatestCRL(ctx context.Context, caID string, expectedVersion *big.Int, latest models.LatestCRLMeta) error
      SetSigner(ctx context.Context, caID, expectedSerial, newSerial string) (bool, error)
  }
  ```
  `UpdateLatestCRL` devuelve `errs.ErrCRLSettingsConflict` (nuevo, en `core/pkg/errs/va.go`) si la versión guardada ya no es `expectedVersion`. `SetSigner` hace `UPDATE … WHERE ca_id = ? AND signer_serial_number = expectedSerial` y devuelve si cambió alguna fila. `UpdateOptions` solo escribe columnas de opciones y devuelve `ErrCertificateNotFound` si salta `crl_settings_signer_cert_fk`.
  Estados: los cambios de estado son del PR 2 (no hay `SetStatus` aún).

- [ ] **Step 1: Write the failing test** en `engines/storage/postgres/test/crl_settings_repo_test.go`: tabla de casos sobre un Postgres con esquemas `ca` y `va` migrados (reutilizar el arranque de `va_signer_fk_test.go`):
  - `TestCRLSettingsRepo_InsertGet`: inserta `{CAID:"a", Status: Active, signer=S1}`; `Get("a")` existe; `Get("zz")` no existe.
  - `TestCRLSettingsRepo_LegacySKILookupAndUniqueness`: `Insert` con `LegacySKI=&"ski1"`; `GetByLegacySKI("ski1")` devuelve `ca_id`; insertar otro con el mismo `legacy_ski` falla.
  - `TestCRLSettingsRepo_UpdateOptionsDoesNotTouchStatusOrLatestCRL`: tras `UpdateOptions`, `Status` y `LatestCRL` intactos.
  - `TestCRLSettingsRepo_UpdateLatestCRLCAS`: con `expectedVersion=0` OK; repetir con `0` devuelve `ErrCRLSettingsConflict`; `Options` intactas.
  - `TestCRLSettingsRepo_SetSignerConditional`: `SetSigner("a","S1","S2")==true`; `SetSigner("a","S1","S3")==false` y el firmante sigue `S2`.
  - `TestCRLSettingsRepo_SignerCertFK`: borrar `ca.certificates` del firmante devuelve error de FK; `UpdateOptions` con un serial inexistente devuelve `errs.ErrCertificateNotFound`.
- [ ] **Step 2: Run to verify it fails** — `cd engines/storage/postgres && CGO_ENABLED=1 go test ./test/ -run TestCRLSettingsRepo -v`. Expected: no compila (`CRLSettings` indefinido).
- [ ] **Step 3: Implement** modelos, interfaz y `PostgresCRLSettingsStore` (`NewCRLSettingsRepository(logger, db) (storage.CRLSettingsRepo, error)`, tabla `crl_settings`, PK `ca_id`). `UpdateLatestCRL` y `SetSigner` con `db.WithContext(ctx).Table("crl_settings").Where(...).Updates(...)` y `RowsAffected`; `UpdateOptions` con `Select` explícito de las cuatro columnas. **No** exponer un `Update` genérico. Renombrar `GetVARoleStorage` → `GetCRLSettingsStorage` en el engine y su test. Actualizar `certstore.go:136` al nuevo nombre de FK `crl_settings_signer_cert_fk`.
  - Nota: depende de la migración (Task 2) para ejecutarse; implementar T2 antes de que este paso pase.
- [ ] **Step 4: Run tests** — mismo comando. Expected: PASS (tras Task 2).
- [ ] **Step 5: Commit** (solo si el usuario lo pide) — `feat(va): add CRLSettings model and scoped repository`.

> Orden de ejecución real: T2 → T1 pasos 3–4 (el repositorio necesita la tabla). Hacer primero el test de migración (T2 step 1–2), la migración, y luego cerrar T1.

---

### Task 2: Migración `va_role` → `crl_settings`

**Files:**
- Create: `engines/storage/postgres/migrations/va/20261111120000_crl_settings.sql`
- Test: `engines/storage/postgres/migrations_test/va_crl_settings_test.go`
- Modify: `engines/storage/postgres/migrations_test/va_signer_fk_test.go` (debe seguir pasando hasta la versión `20261104121000`; no tocar salvo que el rollback lo exija), `engines/storage/postgres/test/migrate_order_test.go`, `engines/storage/postgres/cmd/goose-lamassu/README.md`

**Interfaces:**
- Consumes: esquema `va_role` (con `crl_signer_certificate_serial_number`) y `ca.certificates (serial_number, subject_key_id, key_id)`, `ca.ca_certificates (id, serial_number, creation_ts)`.
- Produces: tabla `va.crl_settings` con columnas `ca_id` (PK), `legacy_ski` (UNIQUE, nullable), `signer_serial_number` (nullable), `validity`, `refresh_interval`, `regenerate_on_revoke`, `status`, `latest_crl_version`, `latest_crl_valid_from`, `latest_crl_valid_until`; FK `crl_settings_signer_cert_fk`; `CHECK (status IN ('ACTIVE','ARCHIVED'))`. `va_role` eliminada.

Reglas de la migración (todas dentro de un bloque `DO $$`, mismo estilo que `20261104121000`):
1. Cada `va_role` se mapea a `ca.ca_certificates.id` donde `ca.certificates.subject_key_id = ca_ski`. Fila nueva `ACTIVE` con `legacy_ski = ca_ski`, firmante = `crl_signer_certificate_serial_number`, resto copiado.
2. Si un rol casa con >1 CA → `RAISE EXCEPTION` listando el rol y los IDs de las CAs.
3. Si no casa ninguna CA (huérfano) → fila `ARCHIVED`, `ca_id = 'legacy-' || ca_ski`, `legacy_ski = ca_ski`, `signer_serial_number = NULL`. (Su `latest_crl_*` se conserva.)
4. Si el firmante de un rol no tiene `key_id` (`ca.certificates.key_id IS NULL`) y el rol NO es huérfano → `RAISE EXCEPTION` listando rol, CA y firmante.
5. Si algún `ca_id` contiene `/` → `RAISE EXCEPTION` listando la CA. Si algún `ca_id` coincide con el `legacy_ski` de otra fila → `RAISE EXCEPTION`.
6. Crear índice/constraints, copiar, `DROP TABLE va_role`. `Down`: recrear `va_role` desde `crl_settings` (mejor esfuerzo: `ca_ski = COALESCE(legacy_ski, <ski del certificado de la CA>)`), `crl_subject_key_id_signer` se reconstruye como en la migración anterior.

- [ ] **Step 1: Write the failing test** `TestCRLSettingsMigration` (tabla, mismo andamiaje que `TestVARoleSignerMigration`: `UpTo(…, 20261104121000)` más tablas `ca.*` simuladas con `id` y `key_id`). Casos con sus aserciones:
  - `1:1`: un rol y su CA → una fila `ACTIVE`, `ca_id` = ID de la CA, `legacy_ski` = SKI, `latest_crl_version` copiada.
  - `huérfano`: rol sin CA → `ARCHIVED`, `ca_id = 'legacy-<ski>'`, `signer_serial_number IS NULL`.
  - `huérfano subordinada`: el certificado de emisor tiene `issuer_meta_id` del padre; sigue siendo `ARCHIVED` con `ca_id` sintético y el ID del padre no se usa.
  - `SKI con dos CAs`: error que contiene el rol y ambos IDs; `va_role` intacta.
  - `firmante sin key_id`: error con rol, CA y firmante; `va_role` intacta.
  - `ca_id con '/'`: error que lista la CA.
  - `ca_id igual a legacy_ski de otra fila`: error.
  - `unicidad legacy_ski`: insertar dos filas con el mismo `legacy_ski` falla.
  - `numeración continúa`: `latest_crl_version` de la fila migrada igual a la de `va_role`.
  - `FK del firmante`: borrar el certificado firmante de una fila `ACTIVE` falla; renombrar su serial se propaga (`ON UPDATE CASCADE`).
  - `rollback`: tras `RollbackMigration(..., "20261111120000_crl_settings")` existe `va_role` con `ca_ski`.
- [ ] **Step 2: Run to verify it fails** — `cd engines/storage/postgres && CGO_ENABLED=1 go test ./migrations_test/ -run TestCRLSettingsMigration -v`. Expected: FAIL (migración inexistente).
- [ ] **Step 3: Implement** el SQL de migración según las reglas anteriores. Actualizar `migrate_order_test.go` y el README de goose si listan tablas.
- [ ] **Step 4: Run tests** — el mismo comando más `go test ./migrations_test/ -run TestVARoleSignerMigration`. Expected: PASS ambos.
- [ ] **Step 5: Commit** (solo si lo pide el usuario) — `feat(va): migrate va_role to crl_settings keyed by CA ID`.

---

### Task 3: Servicio `CRLService` — API de servicio por ID de CA

**Files:**
- Modify: `core/pkg/services/crl.go`, `core/pkg/services/va.go`, `core/pkg/errs/va.go` (`ErrVARoleNotFound` → `ErrCRLSettingsNotFound`; `ErrCRLSettingsNotActive`, `ErrCRLSettingsConflict`), `core/pkg/models/events.go`, `core/pkg/resources/vareq.go`, `core/pkg/services/mock/crl_mock.go`
- Test: `backend/pkg/services/crl_settings_test.go`

**Interfaces:**
- Produces (`core/pkg/services/crl.go`):
  ```go
  type CRLService interface {
      CalculateCRL(ctx context.Context, input CalculateCRLInput) (*x509.RevocationList, error)
      GetCRL(ctx context.Context, input GetCRLInput) (*x509.RevocationList, error)
      GetCRLSettings(ctx context.Context, input GetCRLSettingsInput) (*models.CRLSettings, error)
      GetCRLSettingsList(ctx context.Context, input GetCRLSettingsListInput) (string, error)
      UpdateCRLSettings(ctx context.Context, input UpdateCRLSettingsInput) (*models.CRLSettings, error)
      InitCRLSettings(ctx context.Context, caID string) (*models.CRLSettings, error)
  }
  type GetCRLInput struct { ID string `validate:"required"`; CRLVersion *big.Int `validate:"required"` } // ID = ca_id o legacy_ski
  type CalculateCRLInput struct { CAID string `validate:"required"` }
  type GetCRLSettingsInput struct { CAID string `validate:"required"` }
  type GetCRLSettingsListInput struct { QueryParameters *resources.QueryParameters; ExhaustiveRun bool; ApplyFunc func(models.CRLSettings) }
  type UpdateCRLSettingsInput struct { CAID string `validate:"required"`; Options models.CRLSettingsOptions `validate:"required"` }
  ```
- Produces (`core/pkg/services/va.go`): `VAService` con `GetCRL(ctx, GetCRLResponseInput{ID, Issuer, VerifyResponse})`, `GetCRLSettingsList`, `GetCRLSettingsByID(GetCRLSettingsInput)`, `UpdateCRLSettings`. `resources.CRLSettingsUpdate{ models.CRLSettingsOptions }`.
- Eventos (`events.go`): `EventUpdateCRLSettings = "va.crl-settings.update"`, `EventInitCRLSettings = "va.crl-settings.init"`, `EventCreateCRL` sin cambio (`va.role.crl.create`, no se renombra: es parte del contrato de eventos publicado). Subject `crl/<ca-id>`.

Comportamiento del servicio (en `backend/pkg/services/crl.go`):
- `InitCRLSettings(ctx, caID)`: carga la CA por ID (`caSDK.GetCAByID`); `ErrCANotFound` si no existe; si ya existe la fila → la devuelve sin duplicar (reintento de evento); si no, inserta `ACTIVE` con firmante = serial del certificado de la CA, `LegacySKI = nil`, defaults del spec, `latest_crl.version = 0`; luego `svc.service.CalculateCRL`.
- `crlIssuer(ctx, caID, serial)` (sustituye a la versión por SKI): carga la CA por ID y el certificado firmante; válido si `cRLSign` y mismo `RawSubject` y misma clave pública que la CA; si no, `ErrValidateBadRequest`. Se eliminan `crlIssuerPrecedes` y la búsqueda por SKI.
- `CalculateCRL`: `Get(caID)`; si no existe `ErrCRLSettingsNotFound`; si `Status != ACTIVE` devuelve `ErrCRLSettingsNotActive`; revocados de `caID` (`GetCertificatesByCaAndStatus`); IDP con CDP nuevo y, si `LegacySKI != nil`, también el antiguo, por cada dominio VA (`getDistributionPointExtension(caID string, legacySKI *string)`); escribe `pki/va/crl/<caID>/<n>.crl`; `UpdateLatestCRL(caID, <versión leída>, meta)` y si hay conflicto devuelve error **sin** dejar el fichero huérfano (borrar el fichero escrito, ignorando el error de borrado).
- `GetCRL`: resuelve `ID` → `Get(ID)`; si no existe `GetByLegacySKI(ID)`; si ninguna → `ErrCRLSettingsNotFound`. Versión 0 = `latest`; lectura de bucket: `pki/va/crl/<ca_id>/<n>.crl`, y si falla y `LegacySKI != nil`, `pki/va/crl/<legacy_ski>/<n>.crl`. Sirve en cualquier estado.
- `UpdateCRLSettings`: `crlValidate.Struct`; 404 si no existe; `ErrCRLSettingsNotActive` si no `ACTIVE`; valida firmante con `crlIssuer` solo si el serial cambia respecto al guardado (absorbe #841); `repo.UpdateOptions`.

- [ ] **Step 1: Write the failing test** `backend/pkg/services/crl_settings_test.go` con repo en memoria/mock y `blob` en memoria (`memblob`), CA SDK mock (`core/pkg/services/mock`):
  - `TestInitCRLSettings_OnePerCAEvenIfSharingKey`: dos CAs (`ca-a`, `ca-b`) con el mismo SKI → dos filas, `legacy_ski == nil` en ambas.
  - `TestInitCRLSettings_Idempotent`: segunda llamada no inserta ni falla.
  - `TestCalculateCRL_ListsOnlyOwnRevocations`: `ca-a` y `ca-b` comparten clave y subject; una revocada en cada una → cada CRL contiene solo la suya (aserción por serial).
  - `TestCalculateCRL_IDPContainsNewAndLegacyURLs`: fila migrada (`legacy_ski="3f9a"`) → IDP con `http://va/crl/<ca-id>` y `http://va/crl/3f9a`; fila nueva → solo la nueva.
  - `TestCalculateCRL_CASConflictDoesNotPublish`: el repo mock devuelve `ErrCRLSettingsConflict` → error y no queda fichero `.crl` de esa versión en el bucket.
  - `TestCalculateCRL_NotActiveRejected`: `ARCHIVED` → `ErrCRLSettingsNotActive`.
  - `TestGetCRL_ResolvesCAIDThenLegacySKI`: `GetCRL{ID:"<ca-id>"}` y `GetCRL{ID:"3f9a"}` devuelven la misma CRL; un ID que sea `ca_id` de otra fila y `legacy_ski` de una tercera resuelve por `ca_id` (primero).
  - `TestGetCRL_LegacyBucketFallback`: fichero solo en `pki/va/crl/3f9a/5.crl`, petición de versión 5 → se lee.
  - `TestGetCRL_ArchivedStillServed`.
  - `TestUpdateCRLSettings_NotActiveConflict`, `…_SignerValidatedOnlyWhenChanged` (cambiar solo `Validity` con firmante que ya no valida → OK), `…_InvalidSignerRejected` (sin `cRLSign` → `ErrValidateBadRequest`).
- [ ] **Step 2: Run to verify it fails** — `cd backend && CGO_ENABLED=1 go test ./pkg/services/ -run 'CRLSettings|CalculateCRL|GetCRL' -v`. Expected: no compila / FAIL.
- [ ] **Step 3: Implement** los cambios de interfaz, errores, eventos y `backend/pkg/services/crl.go` según el bloque "Comportamiento". Actualizar `crl_mock.go` a la nueva interfaz.
- [ ] **Step 4: Run tests** — mismo comando. Expected: PASS.
- [ ] **Step 5: Commit** (solo si lo pide el usuario) — `feat(va): resolve CRL generation by CA ID`.

---

### Task 4: Handlers de eventos y job por ID de CA

**Files:**
- Modify: `backend/pkg/services/handlers/va-handlers.go`, `backend/pkg/jobs/va-crl-job.go`
- Test: `backend/pkg/services/handlers/va-handlers_test.go`, `backend/pkg/jobs/va-crl-job_test.go` (adaptar los existentes)

**Interfaces:**
- Consumes: `CRLService` de Task 3.
- Produces: `NewVAEventHandler` con las mismas claves de `DispatchMap` (`ca.create`, `ca.reissue`, `certificate.status.update`); los handlers nuevos de `ca.status.update`/`ca.delete` son PR 2.

Comportamiento:
- `createCAHandler`: `InitCRLSettings(ca.ID)`.
- `reissueCAHandler`: por `ca.Updated.ID`; `GetCRLSettings`; no encontrada → warn y `nil`; no `ACTIVE` → ignora y `nil`; si el firmante guardado es el serial anterior, `UpdateCRLSettings` con el nuevo serial (mismo manejo que hoy de `ErrValidateBadRequest` → warn, mantiene firmante) y luego `CalculateCRL`; si ya es el nuevo, solo `CalculateCRL`; otro firmante → no hace nada.
- `updateCertificateStatus`: busca por `cert.Updated.IssuerCAMetadata.ID` (no por AKI); no encontrada → warn y `nil`; no `ACTIVE` → ignora; `RegenerateOnRevoke` → `CalculateCRL`.
- Job: itera `GetCRLSettingsList`; salta las que no son `ACTIVE`; misma lógica de refresco (#848).

- [ ] **Step 1: Write the failing test** (adaptando los existentes y añadiendo):
  - `TestUpdateCertificateStatus_UsesIssuerCAID`: evento con `IssuerCAMetadata.ID="ca-b"` y AKI compartido con `ca-a` → solo se calcula `ca-b`.
  - `TestUpdateCertificateStatus_IgnoresArchived` y `…_NoSettingsAccepted`.
  - `TestReissueCAHandler_ByCAID_MovesSignerOnlyIfSuperseded` (y retry, y firmante distinto).
  - `TestCreateCAHandler_InitsByID`.
  - `TestCRLMonitorJob_SkipsNonActive`, `TestCRLMonitorJob_RefreshInterval…` (los existentes sobre `CRLSettings`).
- [ ] **Step 2: Run to verify it fails** — `cd backend && CGO_ENABLED=1 go test ./pkg/services/handlers/ ./pkg/jobs/ -v`. Expected: FAIL.
- [ ] **Step 3: Implement** los handlers y el job según el bloque anterior.
- [ ] **Step 4: Run tests** — mismo comando. Expected: PASS.
- [ ] **Step 5: Commit** (solo si lo pide el usuario) — `feat(va): route CRL events and job by CA ID`.

---

### Task 5: CDP de certificados nuevos por ID de CA

**Files:**
- Modify: `backend/pkg/x509engines/x509engine.go` (`CreateRootCA`, `SignCertificateRequest`, `addDistributionPoints`), `backend/pkg/services/ca.go` (llamadas en `CreateCA`~787, `signCertificate`~1666, reissue si aplica)
- Test: `backend/pkg/x509engines/x509engine_test.go` (o el existente más cercano), `backend/pkg/assemblers/tests/ca/` (un caso de CDP si ya hay suite de CA)

**Interfaces:**
- Produces:
  ```go
  func (engine X509Engine) CreateRootCA(ctx context.Context, signer crypto.Signer, keyID string, caID string, subject models.Subject, validity models.Validity, profile models.IssuanceProfile) (*x509.Certificate, error)
  func (engine X509Engine) SignCertificateRequest(ctx context.Context, csr *x509.CertificateRequest, ca *x509.Certificate, caID string, caSigner crypto.Signer, profile models.IssuanceProfile) (*x509.Certificate, error)
  func (engine X509Engine) addDistributionPoints(template *x509.Certificate, crlID string)
  ```
  El CDP es `http://<domain>/crl/<url.PathEscape(crlID)>`. **Importante:** para el CDP de un certificado emitido, el `caID` es el de la CA emisora, no el de la CA que se crea. Para un `CreateCA` raíz, el `caID` recién generado se pasa a `CreateRootCA`; para una subordinada, el CDP de su certificado usa el ID de su padre (`input.ParentID`).

- [ ] **Step 1: Write the failing test**:
  - `TestCreateRootCA_CDPUsesCAID`: `CRLDistributionPoints == ["http://va.example.com/crl/my-ca"]`.
  - `TestSignCertificateRequest_CDPUsesIssuerCAID`: idem con el ID de la CA emisora, aunque el SKI de la CA sea distinto.
  - `TestAddDistributionPoints_EscapesID`: ID `a b` → `…/crl/a%20b`.
- [ ] **Step 2: Run to verify it fails** — `cd backend && CGO_ENABLED=1 go test ./pkg/x509engines/ -v`. Expected: no compila.
- [ ] **Step 3: Implement** y adaptar todos los llamantes (`codegraph_explore "CreateRootCA SignCertificateRequest addDistributionPoints"` para localizarlos, incluidos tests existentes).
- [ ] **Step 4: Run tests** — `cd backend && CGO_ENABLED=1 go test ./pkg/x509engines/ ./pkg/services/ -v`. Expected: PASS.
- [ ] **Step 5: Commit** (solo si lo pide el usuario) — `feat(ca): use CA ID in CRL distribution points`.

---

### Task 6: API HTTP, rutas, SDK, OpenAPI

**Files:**
- Modify: `backend/pkg/controllers/va.go`, `backend/pkg/routes/va.go`, `sdk/va.go`, `backend/pkg/specs/va-openapi.yaml`, `backend/pkg/controllers/va_test.go`, `sdk/va_test.go`
- Modify: `backend/pkg/middlewares/audit/crl.go`, `backend/pkg/middlewares/eventpub/crl.go`, `backend/pkg/middlewares/otel/crl.go` (+ `audit/crl_test.go`)

**Interfaces:**
- Consumes: `CRLService` (Task 3).
- Produces (HTTP):
  - `GET /crl/:id` (público): resuelve `ca_id` y luego `legacy_ski`; 404 si ninguna; `Content-Type: application/pkix-crl`.
  - `GET /v1/crl-settings` (`read`, paginado, filtros `ca_id`, `status`, `legacy_ski`) y `GET /v1/crl-settings/:ca-id` (`read`).
  - `PUT /v1/crl-settings/:ca-id` (`update`): cuerpo `resources.CRLSettingsUpdate`; 400 validación, 404 inexistente o certificado inexistente, **409** `ErrCRLSettingsNotActive`; no regenera la CRL.
  - `/v1/roles/:ca-ski` eliminado. En el SDK: `GetCRL` pasa `ID`.
  - Authz: `pkiAuthz(engine, "va", "crl_settings", logger)` con `Resource("read"|"update", map[string]string{"ca_id": "ca-id"})`.
  - Middlewares: subject de eventos `crl/<caID>`; tipos de evento de Task 3.

- [ ] **Step 1: Write the failing test** (controlador con mock de `CRLService`, gin test; SDK con `httptest`):
  - `TestCRLRoute_ServesByCAIDAndLegacySKI`.
  - `TestPutCRLSettings_NotActiveReturns409`, `…_NotFound404`, `…_BadRequest400`.
  - `TestOldRolesRouteGone`: `GET /v1/roles/x` → 404.
  - `TestContract…` (existe un test de contrato de rutas del VA vía `registerVARoutes`; actualizarlo con las rutas nuevas).
  - SDK: `TestSDK_GetCRLUsesID`, `TestSDK_UpdateCRLSettingsMapsErrors` (409 → `ErrCRLSettingsNotActive`).
  - Middleware: `TestCRLEventPublisher_SubjectUsesCAID` y el audit test existente renombrado.
- [ ] **Step 2: Run to verify it fails** — `cd backend && CGO_ENABLED=1 go test ./pkg/controllers/ ./pkg/middlewares/... -v` y `cd sdk && go test ./ -run VA -v`. Expected: FAIL.
- [ ] **Step 3: Implement** controladores, rutas, SDK, middlewares y reescribir `va-openapi.yaml` (`/crl/{id}`, `/v1/crl-settings`, `/v1/crl-settings/{ca-id}`, esquemas `CRLSettings`, `CRLSettingsUpdate`, respuesta 409).
- [ ] **Step 4: Run tests** — mismos comandos. Expected: PASS. Validar el YAML (`go test ./backend/pkg/specs/...` si existe test, si no, abrirlo con el parser que usa `specs`).
- [ ] **Step 5: Commit** (solo si lo pide el usuario) — `feat(va)!: replace /v1/roles with /v1/crl-settings`.

---

### Task 7: Generación obligatoria del ID de CA en el backend

**Files:** `backend/pkg/services/ca.go`, `ca_id_test.go`, `ca_import_test.go`; `backend/pkg/middlewares/eventpub/ca.go` y test; `core/pkg/services/ca.go`, `core/pkg/resources/careq.go`, `backend/pkg/specs/ca-openapi.yaml`; fixtures y datos de ejemplo afectados.

- [x] Escribir tests: creación e importación generan UUIDv7 y dos operaciones generan IDs distintos. Los controladores aceptan JSON antiguo con `id` de texto, numérico u objeto y devuelven el ID del backend. Verificar almacenamiento, issuer metadata y CDP de raíz con el ID devuelto. Los subjects `ca.create` y `ca.import` usan el ID de salida.
- [x] Ejecutar los tests y comprobar el fallo por respetar o rechazar el ID de entrada; antes de eliminar el campo HTTP, comprobar el 400 al recibir un `id` numérico u objeto.
- [x] Quitar `validCAID`/regex y generar siempre `uuid.NewV7().String()` en el servicio. Eliminar `ID` de `CreateCAInput`, `ImportCAInput`, `CreateCABody`, `ImportCABody` y sus inicializaciones, incluidos SDK y controladores. Retirar `id` de los esquemas OpenAPI de entrada y documentar que se ignora si se recibe. Corregir los subjects y las referencias de fixtures que dependan de IDs elegidos.
- [x] Ejecutar tests por directorio con `CGO_ENABLED=1`: servicios, controladores, eventos, SDK, integración CA/VA y sampledata; revisar el diff y la seguridad. No modificar IDs existentes ni reemisión. No hacer commit.

**Verificación (2026-11-12):** suites de servicios, controladores, middlewares, X.509 y SDK: PASS. Integración CA: PASS (129,936 s), VA: PASS (111,331 s), paquete Postgres: PASS (42,794 s). `CGO_ENABLED=1 go build ./...` y `CGO_ENABLED=1 go vet ./...`: PASS. Revisión del cambio y seguridad sin hallazgos pendientes.

**Impacto:** clientes y scripts deben usar el ID de respuesta. Un ID proporcionado se ignora sin devolver 400. Las restricciones de importación duplicada por certificado se conservan.

---

### Task 8: Authz (`crl_settings`) y renombres restantes

**Files:**
- Modify: `connectors/authz/pki.json`, `connectors/authz/schemas_test.go`, `connectors/authz/cmd/preload/lamassu.caec5d9a-2b67-469c-9e6e-de883643a208.json`, `connectors/authz/cmd/preload/lamassu.03c50968-8b68-46b9-832b-37536816a045.json`, `CHANGELOG.md` (solo si el repo lo mantiene a mano: comprobarlo antes)
- Modify: `backend/pkg/assemblers/va.go` (`GetCRLSettingsStorage`, nombre `crlSettingsRepo`)

**Interfaces:**
- `pki.json`: entidad `entity_type`/`table_name` `crl_settings`, `primary_key` `ca_id`, `schema_name` `va`, `atomic_actions` `["read","update"]` (la acción `delete` entra con PR 2), `global_actions` como hoy, `filterable`: `ca_id` (string), `legacy_ski` (string), `status` (string), `validity`, `refresh_interval`, `signer_serial_number` (string), `regenerate_on_revoke` (bool), `latest_crl_version` (float), `latest_crl_valid_from`/`valid_until` (timestamp).
- Los preloads sustituyen `va_role`/`ca_ski` por `crl_settings`/`ca_id` en sus reglas.

- [ ] **Step 1: Write the failing test** — ajustar `connectors/authz/schemas_test.go` para exigir la entidad `crl_settings` con PK `ca_id` y la ausencia de `va_role`; añadir un caso al test de contrato de rutas del VA (`registerVARoutes`) que compruebe que cada ruta `/v1/crl-settings*` mapea a `crl_settings` con `ca_id`.
- [ ] **Step 2: Run to verify it fails** — `cd connectors/authz && CGO_ENABLED=1 go test ./... -run 'Schema|Contract' -v` y `cd backend && CGO_ENABLED=1 go test ./pkg/routes/... -v`. Expected: FAIL.
- [ ] **Step 3: Implement** los cambios de JSON y el assembler.
- [ ] **Step 4: Run tests** — mismos comandos. Expected: PASS.
- [ ] **Step 5: Commit** (solo si lo pide el usuario) — `feat(authz): rename va_role entity to crl_settings`.

---

### Task 9: Tests de integración del VA y verificación completa

**Files:**
- Modify: `backend/pkg/assemblers/tests/va/main_test.go`, `shared_key_issuer_test.go`, `signer_certificate_test.go`, `setup_test.go` (adaptar a la nueva API)
- Create: `backend/pkg/assemblers/tests/va/crl_settings_by_ca_id_test.go`

- [ ] **Step 1: Write the failing test** (integración, Docker):
  - `TestTwoCAsSameKey_TwoSettingsAndTwoCRLs`: dos CAs creadas sobre la misma clave KMS tienen dos `CRLSettings`, dos CRLs en `/crl/<ca-id>`, cada una con solo sus revocaciones (anti-objetivo del spec: un revocado debe aparecer en la CRL de su CDP).
  - `TestNewCertificateCDPServesItsCRL`: un certificado emitido tras el cambio lleva `…/crl/<ca-id>` y esa URL lo lista cuando se revoca.
  - `TestLegacyURLServesMigratedCRL`: insertar una fila con `legacy_ski` (simulando migración) → `/crl/<ski>` sirve su CRL y el IDP contiene ambas URLs.
  - `TestPutCRLSettings409WhenArchived`.
  - Adaptar `shared_key_issuer_test.go` y `signer_certificate_test.go` (reissue por `ca.Updated.ID`).
- [ ] **Step 2: Run to verify it fails** — `cd backend/pkg/assemblers/tests/va && CGO_ENABLED=1 go test ./... -timeout 300s -v`. Expected: FAIL.
- [ ] **Step 3: Implement** solo lo que falte (los tests deben pasar con las tareas 1–8); corregir cualquier fallo por causa raíz (`superpowers:systematic-debugging`).
- [ ] **Step 4: Verificación completa** (`superpowers:verification-before-completion`), reportando la salida real:
  - `go build ./...` y `go vet ./...` en la raíz (`CGO_ENABLED=1`).
  - Por directorio, como CI: `engines/storage/postgres`, `backend/pkg/assemblers/tests/va`, `backend/pkg/assemblers/tests/ca`, `backend/pkg/controllers`, `backend/pkg/services/...`, `backend/pkg/jobs`, `sdk`, `connectors/authz`, `monolithic` (comprobar `.github/workflows/ci-test.yaml` para la matriz exacta).
  - `grep -rn "VARole\|va_role\|ca-ski\|CASubjectKeyID" --include=*.go --exclude-dir=vendor .` solo debe encontrar migraciones antiguas y la migración nueva (leyendo las coincidencias, no solo contando).
- [ ] **Step 5: Interoperabilidad (manual, antes de publicar)** — `openssl verify -crl_check` con un certificado con CDP antiguo y otro con el nuevo, contra la misma CRL (spec §11.6). Anotar el resultado; no bloquea el merge de código pero sí la publicación.
- [ ] **Step 6: Revisión** — `security-review` sobre el diff y `superpowers:requesting-code-review`; antes, `anthropic-skills:stride-dread-threat-model` sobre el diseño (AGENTS.md: CRL/revocación es trabajo sensible).
- [ ] **Step 7: Commit** (solo si lo pide el usuario) — un commit por tarea o uno final, tipo Conventional Commits con `!` por el cambio de API.

---

## Self-Review

**Cobertura del spec (PR 1):** modelo y columnas §4 → T1/T2 (sin `signer_engine_id/key_id` ni FK de clave, por decisión 2); migración §6 → T2 (incl. huérfanos, firmante sin clave, SKI compartido, `/`, colisión, numeración); URLs/CDP/IDP §7 → T3 (IDP, resolución), T5 (CDP), T7 (generación de IDs); handlers §8 → T4; `crlIssuer` por identidad de CA §8 → T3; `CalculateCRL` con CAS §8 → T3; `UpdateCRLSettings` §8 → T3; repo acotado §8 → T1; job §8 → T4; API §8.1 (sin `DELETE`, PR 2) → T6; authz §8 → T8; SDK/OpenAPI/eventos §8 → T3/T6; bucket y fallback §6 → T3; 409 en `PUT` → T3/T6. Pruebas §13 aplicables a PR 1 → T1, T2, T9.

**Huecos conscientes:** `CalculateCRL` independiente de la fila de la CA (PR 2, §5): en PR 1 sigue cargando la CA por ID, lo cual es válido porque `ARCHIVED` ya no se regenera. La colisión ID↔`legacy_ski` se evita generando siempre UUIDv7 en el backend (decidido por el usuario), no por consulta (T7).

**Consistencia de tipos:** `CRLSettings`, `CRLSettingsOptions`, `CRLSettingsRepo`, `CalculateCRLInput.CAID`, `GetCRLInput.ID`, `UpdateCRLSettingsInput.Options`, `ErrCRLSettingsNotFound/NotActive/Conflict` se usan con los mismos nombres en T1–T9.

**Proporción:** el plan es más corto que el spec y no incluye cuerpos de funciones.

**Riesgos de ejecución:** T1 y T2 se entrelazan (el repo necesita la tabla): ejecutar T2 antes de cerrar T1. T5 cambia firmas públicas del `X509Engine` usadas por tests existentes: localizar todos los llamantes con CodeGraph antes de editar.
