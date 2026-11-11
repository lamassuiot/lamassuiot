# Diseño: Storage Engine Oracle para Lamassu IoT

**Estado:** Propuesta  
**Fecha:** 2026-11-10

## 1. Objetivo y alcance

Implementar un proveedor `oracle` que cumpla las interfaces existentes de
[StorageEngine](../core/pkg/engines/storage/engine.go) y preserve el comportamiento
observable del proveedor PostgreSQL: operaciones, errores, filtros, ordenación,
paginación, integridad y autorización.

La primera versión cubrirá:

- Instalaciones nuevas sobre Oracle Database 26ai.
- Todos los repositorios del Storage Engine, incluidos grupos y eventos de dispositivos.
- Integración con autorización, métricas y trazas.
- Migraciones de versiones futuras del esquema Oracle.
- Pruebas de contrato contra PostgreSQL y Oracle.

El traslado de datos de una instalación PostgreSQL existente queda fuera de
esta primera versión. Requiere un proyecto adicional de exportación,
transformación y validación; instalar un engine Oracle no migra automáticamente
los datos.

### Evidencia disponible

Se realizó una prueba temporal con `go-oracledb v26.4.0`, `gorm-oracle
v1.1.3`, GORM `v1.31.2` y la imagen
`gvenzl/oracle-free:23.26.3-slim-faststart`. Se comprobó:

| Comprobación | Resultado |
|---|---|
| Conexión directa con `database/sql` y `CGO_ENABLED=0` | Pasó, sin Oracle Instant Client instalado en el host |
| GORM conectado mediante el `*sql.DB` de go-oracledb | Pasó |
| `AutoMigrate`, identidad y retorno del ID con `RETURNING` | Pasó en la prueba inicial |
| Escritura y lectura de un campo `map` con `serializer:json` | Pasó |
| `JSON_VALUE`, paginación simple y rollback de transacción | Pasaron |
| Filtro `JSON_EXISTS` con una expresión GORM personalizada | Pasó |

La prueba no cubrió todos los repositorios ni todas las combinaciones de
filtros, tipos de datos y concurrencia. Esos puntos permanecen como criterios
de aceptación pendientes.

Se observaron además estas limitaciones:

- Con la configuración habitual de identificadores entrecomillados, una
  condición SQL sin entrecomillar falló por el tratamiento de mayúsculas y
  minúsculas de Oracle. `SkipQuoteIdentifiers: true` funcionó en el ensayo.
- Un `JSON_EXISTS` con `'$?(@...)'` en SQL raw chocó con el parser de
  placeholders de GORM. Enlazar el path como parámetro dio `ORA-40454`, porque
  Oracle requiere un literal. Una expresión personalizada GORM que escribe un
  path validado como literal y enlaza el valor de comparación sí funcionó.
- Repetir `AutoMigrate` sobre una columna de identidad produjo `ORA-30670`.
- La conexión directa con go-oracledb compiló sin CGO, pero la combinación
  con el dialecto GORM probado no lo hizo porque este importa Godror.

## 2. Arquitectura

```text
                    API / servicios Lamassu
                             |
                 interfaces core/storage
                             |
           +-----------------+-----------------+
           |                                   |
   StorageEngine PostgreSQL            StorageEngine Oracle
           |                                   |
 repositorios PostgreSQL             repositorios Oracle
           |                                   |
 DBQuerier + SQL PostgreSQL          Query builder + SQL Oracle
           |                                   |
 GORM + dialecto PostgreSQL          GORM + dialecto Oracle
           |                                   |
          pgx                         go-oracledb / database/sql
                                               |
                                      Oracle Database 26ai
```

### Estructura propuesta

```text
engines/storage/oracle/
├── engine.go                 # Registro y construcción del engine
├── config/config.go          # Configuración Oracle
├── connection.go             # Pool, GORM, plugins y observabilidad
├── querier.go                # CRUD y ejecución de listados
├── filters.go                # Filtros SQL y SQL/JSON
├── pagination.go             # Bookmarks, offset y recorrido exhaustivo
├── errors.go                 # Traducción de errores Oracle
├── castore.go
├── certstore.go
├── issuance_profile.go
├── devicemanager.go
├── device_groups.go
├── device_events.go
├── dmsmanager.go
├── vastore.go
├── eventstore.go
├── subscriptionstore.go
├── kmsstorage.go
├── migrations/
└── test/
```

Los nombres son orientativos. No se debe duplicar automáticamente todo el
código PostgreSQL: se extraerá únicamente la lógica realmente independiente de
SQL, por ejemplo, la codificación de bookmarks. Los traductores y consultas de
cada dialecto permanecerán separados.

### Registro

Añadir `config.Oracle`, registrar el builder mediante el mecanismo existente y
añadir el registro en [backend/pkg/storage/builder](../backend/pkg/storage/builder).
Los servicios seguirán dependiendo de las interfaces de `core`, no de Oracle.

La selección de PostgreSQL permanecerá sin cambios. Oracle será una
configuración explícita, no un reemplazo automático.

## 3. Driver, GORM y despliegue

### Opción recomendada

- **Driver:** `github.com/oracle/go-oracledb/v26`.
- **Dialecto GORM:** adaptar el dialecto Oracle probado para aceptar ese driver
  sin depender obligatoriamente de la importación de Godror.
- **Conexión:** construir un `*sql.DB` con go-oracledb y entregarlo al dialecto
  mediante `Config.Conn`.
- **Identificadores:** partir de `SkipQuoteIdentifiers: true`, que funcionó en
  el ensayo, y validar nombres reservados, tablas, vistas, aliases y
  asociaciones con los modelos reales.

La prueba mostró que el dialecto actual puede funcionar con go-oracledb, pero
no compila con `CGO_ENABLED=0` porque importa Godror. Se propone resolverlo
mediante un cambio upstream si es posible o, en su defecto, una variante
mantenida y versionada del dialecto. La decisión debe incluir el coste de
mantenimiento y compatibilidad de versiones.

Si se acepta CGO en las imágenes, el dialecto probado puede utilizarse como
primera etapa; esa opción no equivale a un build sin CGO.

### Configuración propuesta

La forma exacta debe seguir las convenciones del proyecto. Como mínimo:

```yaml
storage:
  provider: oracle
  config:
    connect_string: "dbhost:1521/FREEPDB1"
    username: "LAMASSU"
    password: "<secret>"
    max_open_conns: 20
    max_idle_conns: 5
    conn_max_lifetime: "30m"
```

Los valores del pool son ejemplos, no recomendaciones de dimensionamiento. La
configuración debe admitir TCPS y los mecanismos de credenciales ya utilizados
por Lamassu, sin registrar secretos en logs.

La inicialización debe validar la configuración, hacer `PingContext`, registrar
OpenTelemetry y el plugin de autorización, y comprobar la versión del esquema.
Los errores se propagarán explícitamente. No se dependerá de un `ALTER SESSION`
ejecutado una sola vez sobre un pool, ya que otra sesión podría atender la
siguiente consulta.

## 4. Modelo de datos y aislamiento

### Diseño inicial recomendado: un esquema Oracle para Lamassu

Comenzar con un usuario/esquema de aplicación y tablas identificadas por
dominio. Esto simplifica conexiones y permisos cruzados, pero exige revisar
colisiones de nombres y el SQL generado por autorización antes de confirmarlo.

Las relaciones actuales atraviesan dominios:

- Certificados referencian claves KMS.
- La vista [certificates_view](../engines/storage/postgres/migrations/ca/20261104130000_certificates_view.sql)
  deriva `has_private_key` mediante KMS.
- VA referencia el certificado firmante de CRL.

Si el aislamiento operativo por servicio exige esquemas separados, la
alternativa es usar propietarios explícitos y permisos entre ellos. En
cualquiera de los dos casos, el diseño debe garantizar las relaciones y vistas
entre dominios; no bastaría con crear seis conexiones independientes.

### Tipos

| Datos Lamassu | Propuesta Oracle | Validación necesaria |
|---|---|---|
| IDs y seriales | `VARCHAR2` con límites definidos por campo | Longitudes reales, índices y unicidad |
| PEM y textos extensos | `CLOB` | Escritura y lectura de certificados grandes |
| Fechas | `TIMESTAMP WITH TIME ZONE` donde corresponda | Precisión y comparación entre zonas horarias |
| Metadatos, slots, settings y arrays | Tipo `JSON` | Serialización GORM, nulos y documentos grandes |
| UUID | Representación textual consistente con la API | Ordenación y round-trip |
| Booleanos | Representación explícita y consistente | Valores nulos, escaneo GORM y filtros |

Oracle trata cadenas vacías como `NULL` en tipos de texto SQL. Hay que
inventariar los campos donde Lamassu distingue `""` de `NULL` —por ejemplo,
campos de subject usados en búsquedas— y definir una representación o consulta
equivalente. Este es un criterio de paridad, no un detalle cosmético.

## 5. Consultas, filtros y paginación

### Query builder

La implementación Oracle debe conservar el comportamiento de
[DBQuerier](../engines/storage/postgres/utils.go), pero generar SQL Oracle:

- CRUD con contexto y propagación de errores.
- `Count` con los mismos filtros y restricciones que los listados.
- Asociaciones y modelos completos de vuelta.
- Columnas y aliases seleccionados desde una lista permitida.
- Valores enlazados como parámetros, nunca interpolados.

### Filtros JSONPath

La API actual admite expresiones JSONPath y ordenación en JSON. La solución
propuesta es:

1. Analizar y validar el JSONPath recibido, también cuando proceda de un
   bookmark.
2. Traducirlo a un AST intermedio o representación estructurada.
3. Generar el literal SQL/JSON Oracle a partir de ese árbol; enlazar los valores
   comparados mediante `PASSING`.
4. Construir la cláusula mediante una expresión GORM propia, evitando que `?`
   dentro del path sea interpretado como placeholder.
5. Devolver un error explícito para una expresión inválida o cuya equivalencia
   no pueda garantizarse.

**Riesgo abierto:** la prueba solo cubrió un filtro sencillo; no demuestra que
todos los JSONPath aceptados actualmente puedan traducirse con igual
semántica. Antes de declarar paridad hay que construir una matriz de
expresiones y probar los resultados contra PostgreSQL. Rechazar permanentemente
un subconjunto que hoy funciona sería una reducción funcional y requeriría una
decisión explícita.

Para ordenación, [ParseSortJsonPath](../core/pkg/resources/jsonpath.go) ya
define un subconjunto más limitado. Puede reutilizarse la validación, pero la
generación debe preservar también índices de arrays, `last`, tipos, fechas y
orden de nulos.

### Paginación

Mantener el contrato actual:

- Tamaño predeterminado **50** y máximo **1000**.
- Páginas normales mediante offset, `limit + 1` y bookmark con filtros y orden.
- Orden determinista añadiendo columnas únicas; para KMS, `(key_id, engine_id)`.
- Recorrido exhaustivo mediante keyset, no offset, para evitar saltos al
  modificar filas durante el procesamiento.

Los bookmarks actuales se construyen en
[utils.go](../engines/storage/postgres/utils.go). Se propone conservar su
formato y verificar la compatibilidad con bookmarks PostgreSQL existentes. Eso
no garantiza resultados idénticos si la base cambia entre páginas o si las
colaciones difieren: hay que probar ambas condiciones y documentar los límites.

## 6. Integridad y concurrencia

### Certificados y KMS

[CertificatesRepo](../core/pkg/engines/storage/ca.go) y
[KMSKeysRepo](../core/pkg/engines/storage/kms.go) exigen, entre otros:

- Rechazar un certificado que referencia una clave inexistente.
- Impedir borrar una clave usada por un certificado.
- Permitir `ReleaseKey`.
- Mantener la referencia de certificados cuando cambia el ID de una clave.
- Mantener `has_private_key` coherente en las lecturas.

Oracle no ofrece directamente el mismo `ON UPDATE CASCADE` usado en
PostgreSQL. La propuesta es resolver `RenameKey` como operación transaccional
Oracle explícita, coordinada entre instancias y con restricciones de
integridad. El algoritmo concreto —incluidos el orden de cambios, la unicidad
y la estrategia de bloqueo— debe validarse en una prueba de concurrencia antes
de fijarlo.

El callback que renombra o borra la copia de una clave en un motor
criptográfico es una operación externa a la transacción SQL. El contrato
actual de `DeleteWith` reconoce que un fallo de commit posterior puede dejar
divergencia. Oracle debe preservar y documentar ese comportamiento, no prometer
atomicidad distribuida que no existe.

### Otros invariantes

- Recorrido de ancestros y prevención de ciclos en grupos: traducir las
  consultas recursivas de
  [device_groups.go](../engines/storage/postgres/device_groups.go), con pruebas
  de jerarquías y concurrencia.
- Preservar el borrado en cascada de eventos de dispositivos.
- Reproducir la protección del certificado firmante de VA.
- Traducir errores de unicidad y foreign key a los mismos errores de dominio,
  identificando la restricción concreta cuando sea necesario.

## 7. Autorización

No basta con registrar el plugin GORM. El
[plugin de autorización](../connectors/authz/sdk/gorm/plugin.go) inyecta SQL
generado en el contexto, y el
[assembler de Authz](../connectors/authz/pkg/api/assembler.go) contiene
conexiones específicas PostgreSQL.

Por ello hay dos trabajos diferentes:

1. **Engine Lamassu:** aplicar las restricciones de autorización a lecturas
   Oracle, incluidos aliases y vistas, sin ampliar resultados accidentalmente.
2. **Servicio Authz:** si debe consultar y gestionar datos sobre Oracle, adaptar
   también su conexión y generación SQL. Mantener Authz en PostgreSQL no
   demuestra por sí solo que pueda autorizar consultas contra datos almacenados
   en Oracle.

El criterio es probar permisos positivos y negativos, listados, conteos,
asociaciones y relaciones entre entidades. Si Authz no puede operar con Oracle,
el proveedor no debe anunciar paridad completa cuando la autorización esté
habilitada.

## 8. Migraciones

### Instalación nueva

Crear una línea base Oracle que refleje el esquema actual, no copiar sin más el
histórico PostgreSQL. Debe incluir:

1. Tablas y restricciones base.
2. Índices para accesos y filtros reales.
3. Vistas y relaciones entre dominios.
4. Metadatos de versión y comprobación al arrancar.
5. Orden de dependencias: por ejemplo, KMS antes de la FK de certificados;
   certificados antes de la FK de VA.

El migrador debe contemplar que el DDL de Oracle tiene efectos transaccionales
distintos a PostgreSQL: usar pasos verificables, control de versión, bloqueo
de ejecución concurrente y recuperación explícita tras una interrupción. La
prueba detectó un problema al repetir `AutoMigrate`; por eso se propone DDL
versionado explícito, no AutoMigrate como migrador de producción.

### Actualizaciones futuras

Cada cambio de esquema debe tener migraciones PostgreSQL y Oracle, pruebas de
actualización desde la versión anterior y comprobación del estado tras fallos.
Goose se usa actualmente con dialecto PostgreSQL; hay que seleccionar y
validar una solución Oracle o implementar el soporte necesario.

### Migración de datos existente

Como fase separada: herramienta de copia con mapeo de tipos, orden de carga por
dependencias, reconciliación de claves, validación de conteos y referencias, y
estrategia de parada y rollback. No se debe asumir que pueden ejecutarse las
migraciones históricas PostgreSQL directamente sobre Oracle.

## 9. Pruebas y CI

### Suite de paridad

Crear una suite de contrato reutilizable que ejecute los mismos casos contra
PostgreSQL y Oracle:

- Todos los métodos de cada interfaz y errores de dominio.
- JSON: nulo frente a ausente, arrays, números, cadenas, caracteres especiales
  y documentos grandes.
- Todos los operadores de filtro y ordenación, con casos diferenciales.
- Paginación, bookmarks, desempates y recorrido exhaustivo con cambios.
- Relaciones CA–certificado–KMS–VA, claves compuestas y concurrencia.
- Autorización permitida y denegada, incluidos filtros y vistas.
- Migración inicial, actualizaciones y recuperación ante fallos.
- Cancelación, reconexión y agotamiento del pool.

### CI

Añadir un job específico al [workflow de pruebas](../.github/workflows/ci-test.yaml),
con una imagen FreeOracle fijada por versión y preferiblemente por digest.
Esperar al healthcheck, ejecutar las pruebas de contrato y limpiar el
contenedor. Mantener PostgreSQL en CI para detectar regresiones por cualquier
extracción de código compartido.

Oracle Free es adecuada para pruebas funcionales; sus límites hacen que no sea
suficiente para certificar rendimiento productivo. Oracle documenta límites de
dos CPU, 2 GB de RAM y 12 GB de datos de usuario, además de restricciones de
instalación por entorno lógico.

## 10. Plan y puntos de decisión

| Fase | Entregable | Salida requerida |
|---|---|---|
| 1. Base técnica | Dialecto, conexión, esquema y CI Oracle Free | Build y pruebas básicas reproducibles; decisión CGO |
| 2. Consultas | Filtros, JSONPath, paginación y errores | Matriz diferencial PostgreSQL/Oracle sin diferencias no aceptadas |
| 3. Repositorios | CA, certificados, KMS, dispositivos, DMS, VA y alertas | Todos los contratos implementados |
| 4. Integridad y Authz | Relaciones cruzadas, concurrencia y autorización | Pruebas positivas y negativas, incluidas carreras |
| 5. Migraciones y operación | Migrador, documentación y despliegue | Instalación y actualización reproducibles |
| 6. Adopción | Evaluación de migración de datos y carga | Decisión separada sobre traslado y capacidad productiva |

**Decisión recomendada:** continuar con go-oracledb, pero abrir la
implementación con dos pruebas de riesgo antes de comprometer una fecha:
equivalencia del JSONPath admitido y `RenameKey` con integridad y concurrencia.
Son los puntos que la prueba inicial todavía no cubre y que pueden modificar
la complejidad real del proyecto.

## Referencias

- [Oracle Database Driver for Go](https://github.com/oracle/go-oracledb)
- [Dialecto GORM para Oracle](https://github.com/oracle-samples/gorm-oracle)
- [Imagen Oracle Database Free](https://github.com/gvenzl/oci-oracle-free)
- [Restricciones de Oracle AI Database Free](https://docs.oracle.com/en/database/oracle/oracle-database/26/xeinl/licensing-restrictions.html)
