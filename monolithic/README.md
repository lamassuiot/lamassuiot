# Monolito de desarrollo multitenant

`monolithic/cmd/development` levanta en un solo proceso los siete servicios de Lamassu (KMS, CA, VA, Device Manager, DMS Manager, Alerts y Tenant Manager) detrás de un proxy local, con el mismo modelo de seguridad multitenant que el despliegue con Helm. Sirve para probar un cambio en local sin Kubernetes. **No es un entorno de producción ni sustituye la validación en un despliegue real.**

Especificación: `.lamassu/specs/009-monolith-multitenant/` del repositorio de specs.

## Qué reproduce

| Pieza | En el monolito |
| --- | --- |
| Rutas | Proxy con los mismos prefijos que el gateway de Helm: `/api/{kms,ca,va,devmanager,dmsmanager,alerts}/…` y `/api/tenants/…` (Tenant Manager). Las rutas v2 son `/api/<servicio>/api/v2/tenants/<tenantId>/…` |
| Identidad | JWT en todos los servicios con la lista `issuer_jwks` (RS256, audiencia `lamassu-api`). Por defecto, un emisor local de tokens; opcionalmente, IdP externos (`-issuer`) |
| Autorización | Membership en `controlplane` → tenant → rol, con la matriz RBAC aprobada en G2. Cuota por tenant activa (100 req/s, ráfaga 200, como el chart) |
| Base de datos | PostgreSQL con la base `controlplane` y las seis de negocio, migradas como administrador. Los servicios se conectan como `lamassu_app` (`NOSUPERUSER`, `NOBYPASSRLS`, contraseña aleatoria), así que RLS se aplica |
| Llamadas internas | Cada servicio tiene un listener interno con mTLS y una CA interna generada al arrancar; los clientes SDK entre servicios usan `auth_mode: mtls`. El proxy no publica los listeners internos |
| v1 | `503 v1 compatibility is not configured`, como con el chart, salvo `-v1-default-tenant` y `-v1-sunset` juntos |

## Requisitos

- Go (versión de `go.mod`) con `CGO_ENABLED=1` y un compilador C.
- Docker, salvo que se use un PostgreSQL existente con `-postgres-host`.
- `curl` y `jq` para la guía manual.

## Arranque

Desde la raíz de `lamassuiot`:

```bash
CGO_ENABLED=1 go -C monolithic run ./cmd/development \
  -inmemory-eventbus -cryptoengines filesystem -standard-docker-ports=false
```

Con esas opciones solo hace falta un contenedor (PostgreSQL). El arranque tarda unos 30 s y termina con un banner como este (valores de ejemplo):

```text
==============================================================================
 LAMASSU MONOLITH - DEVELOPMENT ENVIRONMENT - NOT FOR PRODUCTION
==============================================================================
Profile: multitenant (JWT + membership + RBAC on v2 routes, RLS with the lamassu_app role, mTLS between services)
Proxy: https://127.0.0.1:8443 and http://127.0.0.1:8080
  prefixes /api/{kms,ca,va,devmanager,dmsmanager,alerts,tenants}/ as the Helm gateway; services and internal listeners on 127.0.0.1
Runtime directory (0700, deleted on Ctrl+C): /tmp/lamassu-monolith-4196774831
PostgreSQL: Docker container 9b4f4386ec9e on 127.0.0.1:32808; services connect as lamassu_app (no superuser, no BYPASSRLS)
Accepted JWT issuers:
  - https://127.0.0.1:41247/realms/lamassu-dev (JWKS https://127.0.0.1:41247/realms/lamassu-dev/jwks)
Local token issuer (127.0.0.1 only; any local process can get a token for any identity): https://127.0.0.1:41247/realms/lamassu-dev
  get a token: curl -s --cacert /tmp/lamassu-monolith-4196774831/monolith-ca.crt -X POST https://127.0.0.1:41247/realms/lamassu-dev/token -d '{"subject":"alice","actor_type":"HUMAN"}'
Tenant provisioners:
  - https://127.0.0.1:41247/realms/lamassu-dev | provisioner
v1 API: disabled (503), as with the Helm chart; use -v1-default-tenant and -v1-sunset to serve it
==============================================================================
MONOLITH READY
```

`Ctrl+C` para el monolito y borra lo que él creó: su contenedor PostgreSQL (y RabbitMQ, Vault… si los lanzó), el emisor local y el directorio propio. No toca contenedores de otros procesos aunque lleven la etiqueta `group=lamassuiot-monolithic`. Un fallo de arranque hace lo mismo y termina con código `1`; una opción no válida termina con código `2` antes de lanzar nada.

## Opciones

| Opción | Por defecto | Efecto |
| --- | --- | --- |
| `-inmemory-eventbus` | `false` | Eventbus en memoria, sin RabbitMQ. Sin esta opción (ni `-disable-eventbus` ni `-use-aws-eventbus`) se lanza RabbitMQ en Docker |
| `-cryptoengines` | `filesystem` | Lista separada por comas: `filesystem`, `vault`, `aws-kms`, `aws-secrets`, `pkcs11` (este exige `-hsm-module-path`). `vault` y `aws-*` lanzan contenedores |
| `-standard-docker-ports` | `true` | Publica los contenedores en sus puertos estándar (PostgreSQL en `127.0.0.1:5432`). Con `false`, puertos aleatorios |
| `-postgres-host`, `-postgres-port`, `-postgres-admin-user`, `-postgres-admin-password` | vacío (`5432`, `postgres`) | Usa un PostgreSQL existente en vez de Docker. El usuario necesita `CREATEDB` y `CREATEROLE`. `-postgres-host` exige la contraseña |
| `-listen` | `127.0.0.1` | IP en la que escucha el proxy. Otra que no sea loopback expone la API a otros equipos y se avisa en el banner. Los servicios y el emisor local siguen en `127.0.0.1` |
| `-https-port`, `-http-port` | `8443`, `8080` | Puertos del proxy (`0`: uno libre; el banner dice cuál) |
| `-dev-issuer` | `true` | Emisor local de tokens. `false` exige al menos un `-issuer` |
| `-issuer issuer=<iss>,jwks=<url https>` | — | IdP externo aceptado por todos los servicios (repetible). El issuer se conserva exacto |
| `-issuer-ca-file <pem>` | — | CA que firma el JWKS de los `-issuer` (repetible) |
| `-provisioner <iss>\|<sub>` | el `provisioner` del emisor local | Identidades que pueden crear organizaciones y tenants (repetible; si se da, sustituye al de por defecto) |
| `-v1-default-tenant <uuid>` y `-v1-sunset <RFC 3339>` | vacío | Solo juntos: v1 se atiende en ese tenant con las cabeceras `Deprecation`, `Sunset` y `Link`. No hay fecha por defecto |
| `-sample-data` | `false` | Datos de ejemplo en el tenant «Demo» (ver abajo) |
| `-disable-monitor` | `false` | Desactiva el job de monitorización criptográfica |

**Rechazadas** (código `2`, con el motivo):

- `-sqlite`: SQLite no aísla tenants (sin RLS, sin rol sin privilegios, sin control plane). Usa PostgreSQL en Docker o `-postgres-host`.
- `-awsiot`: el conector AWS IoT aún no es multitenant.
- `-disable-ui=false`: la UI publicada (`lamassu-ui`) usa v1 sin OIDC. El monolito no lanza ninguna UI; `lamassu-dashboard` se arranca aparte.

## Identidades y tokens

El emisor local (`https://127.0.0.1:<puerto>/realms/lamassu-dev`) emite tokens RS256 para cualquier `subject`, sin autenticación, solo en loopback, con una clave que se genera en cada arranque. **Cualquier proceso local puede pedir un token para cualquier identidad, incluido el provisioner**: es un riesgo aceptado para un entorno de desarrollo (P7) y la razón por la que el proxy no debe exponerse sin motivo.

```bash
curl -s --cacert "$RUNTIME/monolith-ca.crt" -X POST "$TOKEN_URL" \
  -d '{"subject":"alice","actor_type":"HUMAN","ttl":"15m"}' | jq -r .access_token
```

- `actor_type`: `HUMAN`, `SERVICE` o `DEVICE`. `scope` (opcional) limita el token a esos permisos.
- `ttl`: por defecto 15 min; máximo 1 h.
- El `iss` es el del emisor y el `sub`, el `subject` pedido. Una identidad es el par `(iss, sub)`.
- **El puerto del emisor cambia en cada arranque, y con él el `iss`.** Las memberships de un arranque no valen en el siguiente. Con PostgreSQL en Docker no importa (la base también es nueva); con `-postgres-host` y una base reutilizada, las identidades del emisor anterior ya no existen para el nuevo.

Identidades con nombre en la documentación:

| Identidad | Papel |
| --- | --- |
| `provisioner` | Provisioner por defecto: crea organizaciones y tenants. No tiene acceso a datos de ningún tenant |
| `admin-a`, `admin-b` | `tenant_admin` inicial de A y de B en la guía A/B |
| `alice`, `bob` | `pki_admin` en A y en B |
| `carol` | `viewer` en A |
| `demo-admin`, `sample-data`, `demo-operator` | `tenant_admin`, `pki_admin` y `operator` del tenant «Demo» (`-sample-data`) |

Por la matriz RBAC de G2, **KMS solo concede sus operaciones a un `pki_admin` con `actor_type: SERVICE`** y el scope de la operación (`key.read`, `key.import`…); un `pki_admin` humano recibe `403` en `/api/kms/…`. Crear una CA sí funciona con un `pki_admin` humano: CA llama a KMS por el listener interno.

## Datos de ejemplo (`-sample-data`)

Tras arrancar, el monolito:

1. busca o crea, como `provisioner`, la organización «Demo» y el tenant «Demo» con `demo-admin` como `tenant_admin`;
2. como `demo-admin`, da `pki_admin` a `sample-data` y `operator` a `demo-operator`;
3. crea por las rutas v2 de «Demo» perfiles, dos CA raíz (una con una clave generada en cada arranque e importada en KMS con un token `SERVICE` de `sample-data`), certificados, un DMS (como `demo-admin`, que tiene `dms.write`) y 50 dispositivos, 10 de ellos con certificado (como `demo-operator`).

Un fallo no para el monolito: se avisa con el paso que falló. Si ya existía un tenant «Demo» de otro emisor (base reutilizada), se avisa y no se crean datos. Si `-provisioner` sustituye al provisioner por defecto, la provisión da `403` y también se avisa.

## Guía manual: escenario A/B

Es el requisito 8 de la spec 009, el mismo recorrido que la prueba automática `TestMonolithTenantIsolationAB`. Arranca el monolito como en «Arranque» y, en otra terminal, copia del banner la ruta del directorio propio, la URL del token y el contenedor PostgreSQL:

```bash
export RUNTIME=/tmp/lamassu-monolith-XXXXXXXXXX                      # «Runtime directory»
export TOKEN_URL=https://127.0.0.1:NNNNN/realms/lamassu-dev/token     # URL de «get a token»
export PG_CONTAINER=0123456789ab                                      # «PostgreSQL: Docker container …»
export API=https://127.0.0.1:8443
export ISS=${TOKEN_URL%/token}

tok() { curl -s --cacert "$RUNTIME/monolith-ca.crt" -X POST "$TOKEN_URL" -d "{\"subject\":\"$1\",\"actor_type\":\"HUMAN\"}" | jq -r .access_token; }
# call <sujeto o -> <método> <ruta> [cuerpo]: el estado HTTP va a stderr y el cuerpo a stdout.
call() {
  local who=$1 method=$2 path=$3 body=${4:-} auth=() data=() out
  [ "$who" != "-" ] && auth=(-H "Authorization: Bearer $(tok "$who")")
  [ -n "$body" ] && data=(-H 'Content-Type: application/json' -d "$body")
  out=$(curl -sk -X "$method" "${auth[@]}" "${data[@]}" "$API$path" -w $'\n%{http_code}')
  echo "HTTP ${out##*$'\n'}  $method $path ($who)" >&2
  printf '%s\n' "${out%$'\n'*}"
}
TM=/api/tenants/api/v2
```

El proxy usa un certificado autofirmado (`-k`); el emisor, uno de la CA del monolito (`--cacert`).

```bash
# 1. Salud de los siete servicios a través del proxy: 200 cada uno.
for s in kms ca va devmanager dmsmanager alerts tenants; do call - GET /api/$s/health >/dev/null; done

# 2. El provisioner crea la organización y los tenants A y B con su tenant_admin: 201, status ACTIVE.
ORG=$(call provisioner POST $TM/provisioning/organizations '{"name":"Org AB"}' | jq -r .id)
A=$(call provisioner POST $TM/provisioning/tenants "{\"organization_id\":\"$ORG\",\"name\":\"Tenant A\",\"initial_admin\":{\"issuer\":\"$ISS\",\"subject\":\"admin-a\"}}" | jq -r '.id + " " + .status')
B=$(call provisioner POST $TM/provisioning/tenants "{\"organization_id\":\"$ORG\",\"name\":\"Tenant B\",\"initial_admin\":{\"issuer\":\"$ISS\",\"subject\":\"admin-b\"}}" | jq -r '.id + " " + .status')
echo "A=$A B=$B"; A=${A% *}; B=${B% *}

# 3. El provisioner no ve datos de A: 403.
call provisioner GET /api/ca/api/v2/tenants/$A/cas >/dev/null

# 4. Los tenant_admin dan roles (201) y no pueden tocar su propia membership (409) ni gestionar el otro tenant (403).
call admin-a POST $TM/tenants/$A/memberships "{\"issuer\":\"$ISS\",\"subject\":\"alice\",\"role\":\"pki_admin\"}" >/dev/null
call admin-b POST $TM/tenants/$B/memberships "{\"issuer\":\"$ISS\",\"subject\":\"bob\",\"role\":\"pki_admin\"}" >/dev/null
call admin-a POST $TM/tenants/$A/memberships "{\"issuer\":\"$ISS\",\"subject\":\"carol\",\"role\":\"viewer\"}" >/dev/null
OWN=$(call admin-a GET $TM/tenants/$A/memberships | jq -r '.memberships[] | select(.identity_subject=="admin-a") | .id')
call admin-a PATCH $TM/tenants/$A/memberships/$OWN '{"role":"viewer"}' >/dev/null
call admin-a GET $TM/tenants/$B/memberships >/dev/null

# 5. Cada pki_admin crea un perfil y una CA en su tenant: 201.
PA=$(call alice POST /api/ca/api/v2/tenants/$A/profiles '{"name":"profile A","validity":{"type":"Duration","duration":"12h"}}' | jq -r .id)
CA_A=$(call alice POST /api/ca/api/v2/tenants/$A/cas "{\"subject\":{\"common_name\":\"CA A\"},\"key_metadata\":{\"type\":\"ECDSA\",\"bits\":256},\"ca_expiration\":{\"type\":\"Duration\",\"duration\":\"1d\"},\"profile_id\":\"$PA\"}" | jq -r .id)
PB=$(call bob POST /api/ca/api/v2/tenants/$B/profiles '{"name":"profile B","validity":{"type":"Duration","duration":"12h"}}' | jq -r .id)
CA_B=$(call bob POST /api/ca/api/v2/tenants/$B/cas "{\"subject\":{\"common_name\":\"CA B\"},\"key_metadata\":{\"type\":\"ECDSA\",\"bits\":256},\"ca_expiration\":{\"type\":\"Duration\",\"duration\":\"1d\"},\"profile_id\":\"$PB\"}" | jq -r .id)
echo "CA_A=$CA_A CA_B=$CA_B"

# 6. Cada CA solo aparece en su tenant: 200 y una sola CA en cada lista.
call alice GET /api/ca/api/v2/tenants/$A/cas | jq -c '[.list[].id]'
call bob   GET /api/ca/api/v2/tenants/$B/cas | jq -c '[.list[].id]'

# 7. Casos del requisito 5.
call alice GET /api/ca/api/v2/tenants/$B/cas >/dev/null                       # otro tenant: 403
call bob   GET /api/ca/api/v2/tenants/$B/cas/$CA_A                             # CA de A desde B: 404 ...
call bob   GET /api/ca/api/v2/tenants/$B/cas/does-not-exist                    # ... igual que un ID inexistente
curl -sk -o /dev/null -w 'HTTP %{http_code}  cabecera X-Tenant-ID contradictoria\n' \
  -H "Authorization: Bearer $(tok alice)" -H "X-Tenant-ID: $B" "$API/api/ca/api/v2/tenants/$A/cas"   # 400
call carol GET  /api/ca/api/v2/tenants/$A/cas >/dev/null                      # viewer lee: 200
call carol POST /api/ca/api/v2/tenants/$A/cas '{}' >/dev/null                 # viewer no crea CAs: 403
call -     GET  /api/ca/api/v2/tenants/$A/cas >/dev/null                      # sin token: 401

# 8. v1 sin configurar: 503.
call alice GET /api/ca/v1/cas

# 9. En la base de datos, como lamassu_app: 0 filas sin tenant; con app.tenant_id, solo la CA de ese tenant.
docker exec -i "$PG_CONTAINER" psql -U postgres -d ca -At <<SQL
SET ROLE lamassu_app;
SELECT 'sin tenant: ' || count(*) FROM ca_certificates;
BEGIN; SELECT set_config('app.tenant_id', '$A', true); SELECT 'A: ' || id FROM ca_certificates; COMMIT;
BEGIN; SELECT set_config('app.tenant_id', '$B', true); SELECT 'B: ' || id FROM ca_certificates; COMMIT;
SQL
```

Resultado esperado de cada paso:

| Paso | Resultado esperado |
| --- | --- |
| 1 | `HTTP 200` en los siete `/health` |
| 2 | `HTTP 201` ×3; `A=<uuid> ACTIVE B=<uuid> ACTIVE` |
| 3 | `HTTP 403` |
| 4 | `HTTP 201` ×3, `HTTP 200` (listado), `HTTP 409` (propia membership), `HTTP 403` (tenant B) |
| 5 | `HTTP 201` ×4 y los dos ID de CA |
| 6 | `HTTP 200` con `["<CA_A>"]` para alice y `["<CA_B>"]` para bob |
| 7 | `403`; `404` y `404` con el mismo cuerpo salvo el ID; `400`; `200`; `403`; `401` |
| 8 | `HTTP 503` con `v1 compatibility is not configured` |
| 9 | `sin tenant: 0`, `A: <CA_A>`, `B: <CA_B>` (más una línea con el tenant de cada `set_config`) |

Con `-postgres-host`, el paso 9 se hace con `psql` contra ese servidor como administrador (`SET ROLE lamassu_app` evita necesitar la contraseña aleatoria del rol).

## Prueba automática

```bash
CGO_ENABLED=1 go -C monolithic test -tags monolith ./... -run TestMonolithTenantIsolationAB -count=1 -v -timeout 40m
```

Lanza su propio PostgreSQL en Docker y lo borra al terminar (por ID). No la ejecutes a la vez que otras suites con Docker del mismo checkout. El resto de pruebas del monolito: `CGO_ENABLED=1 go -C monolithic test -p 1 ./... -count=1 -timeout 40m`.

## Qué valida y qué no

Valida en local: provisión y ciclo de vida simple de tenants, memberships y sus reglas (último `tenant_admin`, propia membership), JWT con `issuer_jwks`, RBAC de G2, aislamiento en las rutas v2 (`403`, «no encontrado» igual, cabecera contradictoria), RLS con un rol sin privilegios, llamadas internas con mTLS y la política de v1.

**No valida** (sigue siendo trabajo del despliegue real, gate G5 de `001-328`):

- el gateway Envoy y sus reglas (el proxy del monolito solo reproduce los prefijos). En particular, el proxy local **no sanea `x-forwarded-client-cert`**: pasa al servicio las cabeceras que manda el cliente y solo añade la del certificado TLS presentado, mientras que Envoy la sustituye (`forward_client_cert_details: SANITIZE`). Un cliente local puede mandar su propia cabecera con cualquier certificado, así que las pruebas de EST y de autenticación de dispositivos por certificado contra el monolito no valen como prueba del gateway;
- Keycloak/Cognito ni un flujo OIDC real (login, refresh); el emisor local no es un IdP;
- el chart de Helm, sus values, secretos, migraciones como Job y su orden de arranque;
- HSM real, Vault/AWS con permisos reales, carga y escalado;
- el dashboard (`lamassu-dashboard`) y la UI publicada;
- el conector AWS IoT.

## Límites conocidos

- El motor `filesystem` guarda las claves de las CA en `/tmp/gotest` y VA usa `/tmp/lamassuiot/va`, fuera del directorio propio: no se borran al salir. `-sample-data` no choca con las claves de arranques anteriores porque la clave que importa es nueva en cada arranque; para liberar espacio, `rm -rf /tmp/gotest /tmp/lamassuiot/va` con el monolito parado.
- Claves por tenant en `/tmp/gotest` (spec 004, T4.2–T4.6): el engine `filesystem` es global, así que KMS guarda cada clave en `/tmp/gotest/tenants/<tenant>/`, también para el tenant por defecto, y dos tenants pueden importar la misma clave. Al arrancar, KMS mueve a su tenant las claves que siguen en la raíz plana de `/tmp/gotest`, pero solo las que tienen fila en `kms_keys`. Como la base es nueva en cada arranque, las claves de la raíz plana de arranques anteriores no tienen fila: se listan en el log como huérfanas («orphan key … in the flat root») y no se borran ni se asignan a ningún tenant. Si se vuelve a importar una clave que ya está en `tenants/<tenant>/` de un arranque anterior, KMS reutiliza ese material en lugar de fallar. Ver también la spec `009-monolith-multitenant`.
- Con PostgreSQL en Docker, la base es desechable: cada arranque empieza vacío (salvo el tenant por defecto de las migraciones).
- La reserva de puertos internos tiene una carrera pequeña (decisión D7): si otro proceso toma el puerto, el arranque falla con «address already in use» y basta con repetirlo.
- El SDK solo promueve `/v1/…` a v2 cuando la URL base no tiene ruta: para usar el SDK contra el monolito, apunta al puerto del servicio (como hace `-sample-data`), no al proxy con prefijo.
