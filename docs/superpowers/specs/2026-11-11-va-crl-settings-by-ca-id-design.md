# VA: configuración de CRL por CA (de SKI a ID de CA), con ciclo de vida y protección de la clave

- **Fecha:** 2026-11-11
- **Estado:** borrador, pendiente de aprobación
- **Relacionado:** #834 (una CRL por CA), #841 (roles huérfanos), #842 (actualizaciones perdidas; parte del VA), #815 (filas de certificado obsoletas), #847 / #848 (el firmante sigue a la reemisión de la CA), #850 (duplicado de #842)

## 1. Propósito

El VA identifica una CRL por el Subject Key Identifier (SKI) de la CA. Pero una CRL se identifica en realidad por su emisor, que es la CA. Lamassu permite que varias CAs compartan SKI, por ejemplo dos CAs creadas sobre la misma clave del KMS. Cuando pasa, solo una de ellas obtiene rol VA. La CRL de `/crl/<ski>` lista los revocados de una sola CA, y las revocaciones de la otra no llegan a ninguna CRL.

El peor caso son dos CAs con el mismo subject y la misma clave. El verificador acepta la CRL, porque el nombre del emisor y la firma coinciden, pero la CRL no lista las revocaciones de la otra CA. Un certificado revocado se da por válido sin ningún síntoma visible.

Este cambio indexa la configuración de CRL del VA por ID de CA y renombra el concepto de `VARole` a `CRLSettings`. Le da un ciclo de vida (`ACTIVE`, `FINAL`, `ARCHIVED`), para que borrar una CA se gestione de forma explícita en vez de dejar un rol huérfano. Y hace que la base de datos proteja la clave KMS del firmante hasta que se emita la CRL final, y el certificado firmante hasta que la configuración se archive.

### 1.1 Cómo pueden acabar varias CAs con el mismo SKI, y la decisión de partida

Se analizaron tres situaciones para un SKI y las CAs que lo tienen:

| Caso | Cómo se llega | Qué ve un verificador con un certificado de la CA "hermana" |
|---|---|---|
| **1. Una CA por SKI** | El caso normal | CRL correcta |
| **2. Varias CAs, mismo subject y misma clave** | La misma CA importada de nuevo con otro ID, o el mismo subject creado dos veces sobre la misma clave del KMS | La CRL verifica (mismo nombre de emisor y misma clave), pero no lista las revocaciones de la hermana. **Silencioso: se acepta un certificado revocado.** |
| **3. Varias CAs, distinto subject o distinta clave** | `CreateCA` sobre la clave de otra CA con otro subject ("Factory Root" y "Factory Root 2027"), o `ImportCA` con un SKI copiado | La CRL se rechaza (el nombre del emisor o la firma no coinciden). El hard-fail bloquea, el soft-fail deja pasar. |

A futuro, indexar las CRLs por ID de CA resuelve los tres casos para los certificados emitidos después del cambio. Los ya emitidos llevan grabado el CDP `/crl/<ski>`, que no se puede cambiar. Para ellos, el caso 2 necesitaría una CRL de compatibilidad y el caso 3, reemitir los certificados.

**Decisión de partida (del usuario):** se asume que **los casos 2 y 3 no se han dado en ninguna instalación**, es decir, que cada SKI existente pertenece a una sola CA. Sobre esa base se pasa el VA de SKI a ID de CA, sin CRLs de compatibilidad ni procesos de remediación manual. La migración comprueba la suposición y falla si no se cumple (§6).

### 1.2 Nombre: `CRLSettings` en lugar de `VARole`

Al usuario no le gusta el nombre `VARole`. El objeto guarda, para una CA, cómo se genera su CRL (firmante, validez, refresco, regenerar al revocar) y el estado de su última CRL. No se reutiliza entre CAs.

| Opción considerada | Valoración |
|---|---|
| **`CRLSettings`** | **Elegida por el usuario.** Dice lo que es; `status` y `latest_crl` son estado de solo lectura dentro de él. |
| `CRLConfig` | Igual de claro; "config" suena más a fichero de configuración. |
| `CRLProfile` | Engañoso: en Lamassu un *profile* (`IssuanceProfile`) es reutilizable entre CAs, y esto no lo es. |
| `CRLDistributionPoint` | Término de la RFC, pero allí es la *ubicación*, no la configuración de firma. |
| `CRLIssuer` | Descartado: `cRLIssuer` tiene un significado concreto en la RFC 5280 (CRLs indirectas) y se confundiría con los firmantes delegados (#834). |

### 1.3 Compatibilidad con CAs de varios certificados (cross-signing)

Lamassu va hacia un modelo en el que una CA tiene varios certificados: los de reemisión, que ya existen, y en el futuro los de cross-signing, firmados por otras CAs. Para X.509, todos esos certificados son **la misma CA**, porque comparten nombre y clave. Este diseño no implementa el cross-signing, pero no debe cerrarle el paso. Principios que se fijan para ello:

1. **Una CA = (nombre, clave) = un ID de CA = una CRL.** Los certificados alternativos de una CA (reemisión, cross-signing) pertenecen a su mismo ID de CA, nunca a uno nuevo. Si en el futuro el cross-signing se modelara como "otra CA con la misma clave", el emisor X.509 acabaría con CRLs particionadas. La RFC 5280 las permite si el IDP coincide con el CDP, pero son frágiles con verificadores que no comprueban el IDP o con CRLs distribuidas fuera de banda, algo habitual en IoT.
2. **`CRLSettings` no guarda "el certificado actual" de la CA ni su SKI como identidad.** Solo guarda el `ca_id` y el serial del firmante. El SKI solo se guarda para las CAs migradas, porque lo necesita la URL antigua (`legacy_ski`, §4).
3. **El firmante se valida contra la identidad de la CA (nombre y clave), no contra su certificado actual.** Vale cualquier certificado de la CA con ese nombre, esa clave y `cRLSign`. La CRL resultante es la misma para el verificador, llegue a la CA por el camino que llegue.
4. **El ciclo de vida reacciona al estado de la CA, no al de uno de sus certificados.** `FINAL` llega cuando la CA se revoca o caduca *como CA* (evento `ca.status.update`). Hoy el estado de la CA coincide con el de su certificado actual. Con varios certificados, revocar uno solo (por ejemplo, un cross-certificate) no retira la CA: es una revocación de certificado normal y aparece en la CRL de quien lo firmó.
5. **Fechas y emisores, sobre todos los certificados de la CA.** El `nextUpdate` de la CRL final es el `notAfter` más tardío entre los certificados de la CA. Al retirar la CA se regeneran las CRLs de los emisores de **todos** sus certificados. Hoy, en ambos casos, es solo el certificado actual.
6. **Fuera de alcance: rekey** (una CA que cambia de clave conservando el nombre). Necesitaría una CRL por cada clave de la CA, y no se aborda. Reemitir en Lamassu conserva la clave.

### 1.4 Glosario

- **SKI (Subject Key Identifier):** identificador de la clave pública de un certificado, normalmente un hash de ella. Dos CAs sobre la misma clave tienen el mismo SKI. Hoy es la clave con la que el VA identifica una CRL.
- **AKI (Authority Key Identifier):** dentro de un certificado, el SKI de la CA que lo firmó. Hoy lo usa el handler de revocación para saber qué CRL regenerar.
- **CDP (CRL Distribution Point):** extensión que va **dentro de cada certificado**, escrita al emitirlo. Contiene la URL donde un verificador descarga la CRL que puede revocar ese certificado, por ejemplo `http://va.example.com/crl/3f9a…c1`. No se puede cambiar después de emitir el certificado.
- **IDP (Issuing Distribution Point):** extensión que va **dentro de la CRL**. Indica a qué punto de distribución pertenece la CRL. La RFC 5280 §6.3.3 obliga al verificador a comprobar que el IDP de la CRL coincide con el CDP del certificado, para no usar una CRL de un ámbito en otro distinto. Puede contener varias URLs.
- **CRL final:** la última CRL que publica una CA, al revocarla. Lista todas sus revocaciones y es válida hasta que caduca la propia CA, porque no habrá más.
- **Clave retenida / certificado retenido:** mientras una `CRLSettings` está `ACTIVE`, la base de datos no deja que su certificado firmante suelte su clave KMS. Mientras está `ACTIVE` o `FINAL`, no deja borrar el certificado firmante (§4).

## 2. Objetivos, no objetivos y anti-objetivos

**Objetivos**
- Una `CRLSettings` por CA, indexada por ID de CA. Dos CAs que comparten clave o SKI dejan de interferir entre sí.
- Los certificados emitidos antes del cambio siguen funcionando: su CDP `/crl/<ski>` sirve la misma CRL que hoy.
- Un ciclo de vida de la CRL ligado al de la CA: una CRL final cuando la CA se revoca, y una configuración archivada cuando se borra.
- La clave KMS del firmante no se puede borrar ni soltar hasta que se emite la CRL final, y el certificado firmante no se puede borrar hasta que se archiva la configuración. Lo garantiza la base de datos, sin coordinación entre servicios.
- Sin actualizaciones perdidas sobre la fila de configuración (la parte del VA de #842).

**No objetivos**
- Firmantes de CRL delegados (#834, problema 2). Fase posterior.
- Rechazar SKIs que colisionan en `ImportCA`. Fase posterior.
- CRLs para CAs importadas. El VA no procesa `ca.import` hoy, y este cambio no lo añade.
- CRLs indirectas.
- Arreglar #842 en tablas que no sean las del VA.

**Anti-objetivos** (sería un fracaso aunque el código funcione)
- Un certificado revocado que un verificador acepta porque la CRL de su CDP no lo lista.
- Una actualización que cambia sin avisar qué CRL se sirve en una URL `/crl/<ski>` existente.
- Una clave KMS borrada cuando todavía hace falta para firmar una CRL que el VA debe publicar.
- Una clave que nunca se borra tras desaparecer su CA y su configuración, sin forma de encontrarla ni limpiarla.

## 3. Restricciones y suposiciones

- **Suposición, decidida por el usuario (§1.1):** en todas las instalaciones existentes cada SKI pertenece a una sola CA (caso 1). Los casos 2 y 3 no se han dado. La migración lo comprueba y falla de forma explícita si no se cumple (§6).
- Los esquemas de CA, KMS y VA están en la misma base de datos de Postgres. Esto ya es un requisito: desde #832 la migración del VA crea una FK hacia `ca.certificates`. El orden de migración es `kms`, luego `ca`, luego `va`.
- `DeleteCA` conserva la fila del certificado de la CA, porque la CA padre la necesita para su CRL y su OCSP. Suelta la clave KMS con `ReleaseKey` (`UPDATE certificates SET key_id = NULL`) y después la borra, salvo que otro certificado siga referenciándola. Este diseño mantiene la liberación y el borrado, pero `DeleteCA` comprueba primero que la liberación está permitida, y si no lo está falla con 409 antes de cambiar nada (§9).
- `UpdateCAStatus` revoca los certificados de la CA de forma síncrona y solo después publica `ca.status.update`. El job de caducidad de CAs también pasa por `UpdateCAStatus`, así que una CA caducada publica el mismo evento.
- El VA consume `ca.#` y `certificate.#` de colas separadas. El orden de entrega entre ellas no está garantizado.
- `GetCertificatesByCaAndStatus` no necesita que exista la fila de la CA, así que los revocados se pueden listar por ID de emisor aunque la CA se haya borrado.

## 4. Modelo de datos

La tabla `va.va_role` se sustituye por `va.crl_settings`, y el modelo `VARole` / `VACRLRole` por `CRLSettings`.

| Columna | Tipo | La escribe | Notas |
|---|---|---|---|
| `ca_id` | text, PK | creación, migración | **Sin FK hacia la CA**: la fila tiene que sobrevivir a la CA. |
| `legacy_ski` | text, único, nullable | solo la migración | El SKI de las filas migradas desde `va_role`: `/crl/<legacy_ski>` se resuelve a esta fila. `NULL` en las CAs creadas después del cambio. No se guarda el SKI de las CAs nuevas porque no se usa para nada, y no guardarlo evita atar la identidad de la configuración a una clave concreta (§1.3). |
| `signer_serial_number` | text, nullable | `PUT`, handler de reissue, transiciones de estado | El certificado firmante. |
| `signer_engine_id` | text, nullable | solo el VA, a partir del certificado | **Copia de la clave del certificado firmante**, no un dato independiente. La FK compuesta obliga a que coincida con el `engine_id` actual del certificado; existe solo para poder expresar esa FK. No se puede editar por la API. |
| `signer_key_id` | text, nullable | solo el VA, a partir del certificado | Ídem, con el `key_id`. Que la clave existe en el KMS lo garantiza `certificates_key_fk` (certificado → `kms.kms_keys`). No se añade una FK directa a `kms.kms_keys`: no aportaría nada y crearía dos caminos de propagación (`ON UPDATE CASCADE`) hacia la misma fila. |
| `validity` | text (duración) | `PUT` | |
| `refresh_interval` | text (duración) | `PUT` | `"0"` desactiva la regeneración por intervalo (#848). |
| `regenerate_on_revoke` | bool | `PUT` | |
| `status` | text: `ACTIVE`, `FINAL`, `ARCHIVED` | solo el VA | Solo lectura en la API. |
| `latest_crl_version` | numeric | `CalculateCRL` | |
| `latest_crl_valid_from` | timestamptz | `CalculateCRL` | |
| `latest_crl_valid_until` | timestamptz | `CalculateCRL` | |

Restricciones:

```sql
-- En ca.certificates. Trivialmente única, porque serial_number es la clave primaria.
-- Solo existe para que crl_settings pueda referenciar las tres columnas juntas.
ALTER TABLE ca.certificates
  ADD CONSTRAINT certificates_serial_key_uq UNIQUE (serial_number, engine_id, key_id);

-- En va.crl_settings
-- Protege el CERTIFICADO firmante de ser borrado, hasta ARCHIVED.
CONSTRAINT crl_settings_signer_cert_fk
  FOREIGN KEY (signer_serial_number)
  REFERENCES ca.certificates (serial_number)
  ON DELETE NO ACTION ON UPDATE CASCADE,
-- Protege la CLAVE del firmante (el certificado no puede soltarla), hasta FINAL.
CONSTRAINT crl_settings_signer_key_fk
  FOREIGN KEY (signer_serial_number, signer_engine_id, signer_key_id)
  REFERENCES ca.certificates (serial_number, engine_id, key_id)
  ON DELETE NO ACTION ON UPDATE CASCADE,
-- Qué columnas del firmante tiene cada estado.
CONSTRAINT crl_settings_signer_by_status CHECK (
     (status = 'ACTIVE'   AND signer_serial_number IS NOT NULL
                          AND signer_engine_id IS NOT NULL AND signer_key_id IS NOT NULL)
  OR (status = 'FINAL'    AND signer_serial_number IS NOT NULL
                          AND signer_engine_id IS NULL     AND signer_key_id IS NULL)
  OR (status = 'ARCHIVED' AND signer_serial_number IS NULL
                          AND signer_engine_id IS NULL     AND signer_key_id IS NULL))
```

Las dos protecciones terminan en momentos distintos porque protegen cosas distintas:
- **La clave** solo hace falta para firmar CRLs, y la última es la CRL final. La transición a `FINAL` pone `signer_engine_id` y `signer_key_id` a `NULL`. Con `MATCH SIMPLE`, la FK compuesta deja de aplicarse y el certificado puede soltar su clave.
- **El certificado** sigue protegido hasta `ARCHIVED`, mediante la FK solo sobre el serial.

El `CHECK` exige las tres columnas del firmante mientras está `ACTIVE`. Con `MATCH SIMPLE`, un solo `NULL` desactivaría la FK compuesta sin avisar.

Qué hace la base de datos con el certificado firmante, según el estado:

| Operación sobre `ca.certificates` | `ACTIVE` | `FINAL` | `ARCHIVED` |
|---|---|---|---|
| Borrar la fila | ❌ `NO ACTION` → `ErrCertificateInUse` (409) | ❌ igual | ✅ |
| `ReleaseKey` (`key_id = NULL`) | ❌ el `NULL` se propaga a `crl_settings` y el `CHECK` falla | ✅ | ✅ |
| Mover la clave (`engine_id`/`key_id` nuevos) | ✅ se propaga: la configuración sigue al certificado | ✅ | ✅ |
| Renombrar el serial | ✅ se propaga | ✅ se propaga | ✅ |
| Guardar la fila entera sin cambiar la clave | ✅ no cambia ningún valor referenciado | ✅ | ✅ |

Ejemplo de filas tras el cambio, con la CA `planta` (SKI `3f9a…c1`) migrada desde `va_role` y la CA `linea-2` creada después sobre la misma clave:

| `ca_id` | `legacy_ski` | `status` | Se sirve en |
|---|---|---|---|
| `planta` | `3f9a…c1` | `ACTIVE` | `/crl/planta` y `/crl/3f9a…c1` (certificados antiguos) |
| `linea-2` | `NULL` | `ACTIVE` | solo `/crl/linea-2` |

Mientras la configuración está `ACTIVE`, la clave KMS queda protegida de forma transitiva: `crl_settings` → certificado → `kms.kms_keys`. El certificado no puede soltar la clave, y el KMS ya rechaza borrar una clave que un certificado referencia (`ErrKeyInUse`). El VA nunca referencia claves directamente.

## 5. Ciclo de vida

```
ACTIVE ──CA revocada (motivo ≠ certificateHold)──► FINAL ──ca.delete──► ARCHIVED ──purga──► (fila borrada)
   │         (CRL final, después se suelta la clave)  ▲  (se suelta el certificado)
   └──CA caducada (sin CRL, se suelta la clave)───────┘
```

`DeleteCA` se rechaza mientras la configuración está `ACTIVE` (§9), así que una CA solo se borra cuando su configuración ya es `FINAL`. La transición `ACTIVE → ARCHIVED` se mantiene por robustez, a través de la reconciliación, por si alguna vez aparece una configuración `ACTIVE` de una CA que ya no existe.

| Disparador | Transición | Acción |
|---|---|---|
| `ca.create` | se crea `ACTIVE` | Firmante = el certificado de la CA, con su motor y su clave. Se genera la primera CRL. |
| `ca.status.update`, CA revocada con motivo ≠ `certificateHold` | `ACTIVE → FINAL` | Se genera la **CRL final**, con `nextUpdate` = el `notAfter` más tardío entre los certificados de la CA (hoy, el de su certificado actual; §1.3). Después, en un solo `UPDATE`, `status = 'FINAL'` y `signer_engine_id`/`signer_key_id` a `NULL`, lo que permite a la CA borrar la clave. Si la generación falla, se devuelve el error para que el evento se reintente. **También se regeneran las CRLs de las CAs emisoras** de los certificados de la CA (hoy, solo la de su certificado actual, localizada por `Updated.Certificate.IssuerCAMetadata.ID`; se omiten las raíces autoemitidas), si están `ACTIVE` y tienen `regenerate_on_revoke`. Motivo: `UpdateCAStatus` no publica `certificate.status.update` por el certificado de la propia CA, así que hoy una subordinada revocada no aparece en la CRL de su padre hasta el siguiente refresco. *(Hallazgo de la revisión; decisión mía incluirlo.)* |
| `ca.status.update`, CA revocada con `certificateHold` | ninguna | Un hold es reversible: la configuración sigue `ACTIVE`. Por eso una CA en hold no se puede borrar hasta revocarla definitivamente (§9). |
| `ca.status.update`, CA caducada | `ACTIVE → FINAL` | Sin CRL: una CRL firmada por una CA caducada no es de confianza, y todos los certificados de la CA ya fallan la validación de la cadena. El mismo `UPDATE` pone `signer_engine_id`/`signer_key_id` a `NULL`. |
| `ca.delete` | `FINAL → ARCHIVED` (también desde `ACTIVE`, ver arriba) | En un solo `UPDATE`, `status = 'ARCHIVED'` y la columna del firmante que queda (`signer_serial_number`) a `NULL`. Esto suelta el certificado firmante. |
| Job de monitorización, reconciliación | cualquiera no archivada → el estado que corresponda a la CA | Para cada configuración no archivada, se lee la CA por ID: si no existe → `ARCHIVED`; si está revocada (motivo ≠ hold) → `FINAL`, con su CRL final (la clave sigue retenida mientras está `ACTIVE`); si está caducada → `FINAL`. Cubre los eventos perdidos y la primera ejecución tras la migración (§6). *(Decisión mía.)* |
| `DELETE /v1/crl-settings/{ca-id}` | `ARCHIVED → borrada` | Solo desde `ARCHIVED`; si no, 409. Los ficheros de CRL ya publicados se quedan en el bucket. Necesita una acción nueva de authz (`delete`) sobre la entidad. |

Reglas:
- **Las transiciones solo avanzan.** Cada una es un `UPDATE` condicional con un conjunto explícito de estados de origen: `→ FINAL` usa `WHERE status = 'ACTIVE'`, y `→ ARCHIVED` usa `WHERE status IN ('ACTIVE', 'FINAL')`. Un evento tardío o reentregado no puede hacer retroceder una configuración. No hay que comparar los valores de texto con `<`: alfabéticamente, `ARCHIVED` va antes que `FINAL`.
- **Las CRLs se sirven en cualquier estado.** `GET /crl/...` devuelve la última CRL publicada para configuraciones `ACTIVE`, `FINAL` y `ARCHIVED`. Solo devuelve 404 si ninguna configuración coincide o si nunca se publicó nada.
- **Solo se regeneran las configuraciones `ACTIVE`**: por el job de monitorización, por eventos de revocación y por el handler de reissue. Los eventos de una configuración que no está `ACTIVE` se aceptan y se ignoran.
- **`PUT /v1/crl-settings/{ca-id}`** sobre una configuración que no está `ACTIVE` devuelve 409, con un mensaje que indica el estado.
- **`CalculateCRL` no debe depender de la fila de la CA.** Usa el `ca_id` y el firmante guardados. Como `DeleteCA` no puede ejecutarse antes de `FINAL`, la CRL final en sí no lo necesita, pero así la reconciliación y cualquier regeneración tardía no dependen del estado del servicio CA.

## 6. Migración (esquema `va`)

1. Se crea `crl_settings` y se copia en ella cada fila de `va_role`, como `ACTIVE`:
   - `ca_id` = el ID de la CA de `ca.ca_certificates` cuyo certificado tiene `subject_key_id = ca_ski`;
   - `legacy_ski = ca_ski`;
   - firmante = el `crl_signer_certificate_serial_number` actual, junto con el `engine_id` y el `key_id` de ese certificado;
   - `latest_crl_*` se copian tal cual.

   Las CAs ya revocadas o caducadas también migran como `ACTIVE`. La primera ejecución de la reconciliación del job (§5) las pasa a `FINAL` y genera su CRL final mientras la clave todavía existe. SQL no puede firmar una CRL, así que esto no se puede hacer dentro de la migración.
2. **Comprobación de la suposición:** si un rol coincide con más de una CA, se lanza una excepción que lista el rol y las CAs.
3. **Roles sin CA** (CA borrada, #841): el ID de la propia CA no se puede recuperar. El `IssuerCAMetadata.ID` del certificado es el ID del *padre* en las subordinadas, y la fila de `ca_certificates` ya no existe. Se insertan como `ARCHIVED`, con un `ca_id` sintético (`legacy-<ski>`), `legacy_ski = ca_ski` y las columnas del firmante a `NULL`. Su última CRL publicada sigue accesible en `/crl/<ski>`. *(Decisión mía.)*
4. **Roles cuyo certificado firmante no tiene `key_id`:** tampoco pueden firmar una CRL hoy, y el `CHECK` no los admite como `ACTIVE`. **La migración falla** y lista cada rol, su CA y su firmante, para que el operador apunte el rol a un firmante con clave, o arregle la referencia a la clave del certificado, antes de actualizar. *(Decidido por el usuario.)*
5. Se añade `certificates_serial_key_uq` en `ca.certificates`, y después las dos FKs y el `CHECK` por estado (§4).
6. Se borra `va_role`.
7. La numeración de CRL continúa desde `latest_crl_version`.

Bucket: a partir de ahora los ficheros de CRL se escriben en `pki/va/crl/<ca-id>/<n>.crl`. En las filas con `legacy_ski`, `GetCRL` para una versión concreta prueba primero esa ruta y después `pki/va/crl/<legacy_ski>/<n>.crl`. No se mueve ningún fichero.

## 7. URLs, CDP e IDP

- **CDP de los certificados nuevos:** `http://<dominio-va>/crl/<ca-id>`. *(Decidido por el usuario.)* `addDistributionPoints` recibe el ID de CA en lugar del SKI.
- **`GET /crl/<id>`** tiene un único segmento de ruta para las dos formas, así que se resuelve en este orden:
  1. la configuración con `ca_id = <id>`;
  2. si no la hay, la configuración con `legacy_ski = <id>` (el CDP antiguo de los certificados emitidos antes del cambio).

  Las dos funcionan aunque la CA se haya borrado. La forma antigua **nunca** se resuelve en tiempo de ejecución buscando "la CA con este SKI": una CA creada más tarde sobre la misma clave no debe poder quedarse con una URL existente.
- **Colisión entre las dos formas:** `CreateCA` e `ImportCA` generan siempre un UUIDv7 en el backend. Cualquier `ID` enviado por el cliente se ignora, sin error. El UUID con guiones no coincide con un SKI hexadecimal sin guiones. La migración sigue rechazando colisiones entre IDs existentes y `legacy_ski`.
- **IDP de cada CRL:** las URLs de todos los certificados que cubre. En una CA migrada, la URL nueva y la antigua para cada dominio del VA. En una CA nueva, solo la nueva. La RFC 5280 §6.3.3 exige que el IDP coincida con el CDP del certificado.
- **Identidad de CA:** el servicio genera el UUIDv7 antes de emitir el certificado y lo devuelve en la respuesta. Se conserva el ID al reemitir, en las CAs existentes y al restaurar una copia de seguridad. Importar una CA nueva genera otro ID. El campo `ID` se elimina de `CreateCAInput`, `ImportCAInput`, `CreateCABody` e `ImportCABody`, así como del SDK y OpenAPI. Un `id` en JSON antiguo se ignora como campo desconocido. Los eventos usan `output.ID`. Los IDs existentes no se renombran: se usa `url.PathEscape`, y un `/` hace fallar la migración.

## 8. Cambios de comportamiento por componente

| Componente | Cambio |
|---|---|
| `createCAHandler` / `InitCRLRole` → `InitCRLSettings` | Por `ca.ID`. Una configuración por CA, aunque las CAs compartan clave. Se acaba el "ya existe, se reutiliza" por SKI. |
| Handler de revocación | Busca la configuración por `cert.IssuerCAMetadata.ID` en lugar del AKI. Se ignora si no está `ACTIVE`. Si no hay configuración, el evento se acepta (comportamiento de #848). |
| Handler de reissue (#848) | Por `ca.Updated.ID`. Solo mueve el firmante si es el certificado sustituido, ahora con un `UPDATE` condicional sobre las columnas del firmante (`… WHERE signer_serial_number = <anterior>`) que incluye el motor y la clave del certificado nuevo. |
| Nuevo: handler de `ca.status.update` | Transiciones a `FINAL`, la CRL final y la CRL de la CA emisora (§5). |
| Nuevo: handler de `ca.delete` | Transición a `ARCHIVED` (§5). |
| `crlIssuer` | Se sustituye por "cargar la CA por ID y validar el firmante contra su identidad": mismo subject y misma clave que la CA, más `cRLSign`. Se compara con la identidad de la CA, no con su certificado actual, para que valga cualquier certificado de la CA (§1.3). Desaparecen `crlIssuerPrecedes` y todas las búsquedas por SKI. |
| `CalculateCRL` | Lista los revocados de `ca_id`. Solo escribe `latest_crl_*`, con compare-and-swap sobre la versión que leyó. Si hay conflicto, devuelve error sin publicar el fichero. Firma con el firmante guardado. No necesita la fila de la CA (§5). |
| `UpdateVARole` → `UpdateCRLSettings` | Solo escribe las columnas de configuración. Valida el firmante solo cuando cambia, lo que absorbe #841. 409 si no está `ACTIVE`. |
| Repositorio del VA | Solo métodos acotados: insertar, actualizar la configuración, actualizar la última CRL (con CAS), cambiar de estado (con CAS), fijar el firmante (con CAS), obtener, listar, purgar. **Sin un `Update` genérico de fila entera.** |
| Job de monitorización | Solo regenera configuraciones `ACTIVE`, y ejecuta la reconciliación de §5. |
| Servicio CA, `DeleteCA` | Comprueba **antes de cualquier cambio** que la clave se puede soltar, y devuelve 409 si la configuración de CRL de la CA sigue `ACTIVE` (§9). La liberación y el borrado de la clave siguen como hoy. |
| API | Endpoints nuevos de gestión, ver §8.1. `/v1/roles/:ca-ski` **se elimina**, sin ruta de compatibilidad. *(Decidido por el usuario.)* La UI (repositorio aparte) tiene que pasar a los endpoints nuevos. |
| Authz | La entidad `va_role` (PK `ca_ski`) pasa a `crl_settings` (PK `ca_id`) en `connectors/authz/pki.json`, con una acción nueva `delete` para la purga. Las políticas precargadas cambian en consecuencia. El servicio de authz aún no se ha publicado, así que no hay políticas guardadas que migrar. *(Confirmado por el usuario.)* |
| SDK, OpenAPI, eventos | Renombrados y por ID de CA. El subject de los eventos pasa de `crl/<ski>` a `crl/<ca-id>`. |

### 8.1 API de gestión

Bajo el `/v1` del VA, protegida por authz sobre la entidad `crl_settings`:

| Método y ruta | Acción authz | Comportamiento |
|---|---|---|
| `GET /v1/crl-settings` | `read` | Listado paginado con los parámetros habituales `filter`/`sort_by`/bookmark. Filtrable al menos por `ca_id`, `status` y `legacy_ski`. |
| `GET /v1/crl-settings/{ca-id}` | `read` | Una configuración, con `status`, `legacy_ski` y `latest_crl` de solo lectura. 404 si no existe. |
| `PUT /v1/crl-settings/{ca-id}` | `update` | Sustituye los campos editables: serial del firmante, `validity`, `refresh_interval`, `regenerate_on_revoke`. El VA obtiene el motor y la clave del firmante a partir del certificado. El firmante solo se valida cuando cambia. 409 si la configuración no está `ACTIVE`. No regenera la CRL. |
| `DELETE /v1/crl-settings/{ca-id}` | `delete` | Purga. Solo desde `ARCHIVED`; si no, 409. |

Las configuraciones solo las crea el VA (`ca.create`, migración). No hay `POST`. *(Decisión mía: crearlas a mano, por ejemplo para CAs importadas, queda fuera de alcance.)* Tampoco hay un endpoint para forzar una regeneración. Si se quiere, hay que pedirlo.

## 9. Borrar una CA y su clave

La clave solo está protegida mientras la configuración está `ACTIVE` (§4). Una vez emitida la CRL final (`FINAL`), el certificado puede soltarla. Por eso `DeleteCA` nunca tiene que dejar una clave atrás: se rechaza mientras la CRL final esté pendiente. *(Decidido por el usuario.)*

Nuevo orden en `DeleteCA`:

1. Elegibilidad (sin cambios): revocada, caducada o `ImportedWithoutKey`.
2. **Comprobar que los certificados de la CA pueden soltar su clave.** Si la configuración de CRL de la CA sigue `ACTIVE`, la liberación viola el `CHECK`. La CA traduce esa violación a un error nuevo, que se devuelve como **409** con un mensaje del tipo "la CRL final de la CA X aún no se ha emitido; reinténtalo en unos segundos". Si la CA está revocada con `certificateHold`, el mensaje indica que hay que revocarla definitivamente primero, porque un hold nunca llega a `FINAL`.
3. Operaciones en cascada, borrado de la fila de la CA, liberación y borrado de la clave: como hoy. Si la clave la comparte otra CA, `ErrKeyInUse` hace que se conserve, igual que hoy.

Requisitos del paso 2:
- **No puede haber ningún paso destructivo ni visible desde fuera antes de que la comprobación pase**: ni revocaciones en cascada, ni borrado de filas, ni eventos.
- La forma de comprobarlo queda a criterio de quien lo implemente. Por ejemplo: hacer la liberación y el borrado de la fila de la CA en una sola transacción, o probar la liberación en una transacción que se deshace. Como `FINAL` y `ARCHIVED` son irreversibles, una comprobación que ha pasado sigue siendo válida.

Consecuencias:
- **No queda ningún estado pendiente.** La clave se borra dentro de `DeleteCA`, como hoy. No hay nada que reintentar después.
- **La CRL final está garantizada** para toda CA revocada que tenga configuración, porque la CA no se puede borrar antes de emitirla.
- Las CAs sin configuración (`ImportedWithoutKey`, las importadas en general, las instalaciones sin VA) no se ven afectadas: no hay nada que violar.
- **`DeleteCA` depende de que el VA** haya procesado la revocación o la caducidad. Normalmente son milisegundos. Si el VA está caído, no se pueden borrar CAs hasta que vuelva (§11).

## 10. Decisiones

Decididas por el usuario:
- Formato de URL de la CRL: `/crl/<ca-id>` (§7).
- El servicio de authz no se ha publicado: no hay políticas guardadas que migrar (§8).
- Endpoints de gestión para `CRLSettings`; el antiguo `/v1/roles/:ca-ski` se elimina sin ruta de compatibilidad (§8, §8.1).
- Los roles cuyo firmante no tiene `key_id` hacen fallar la migración (§6).
- La clave se protege hasta `FINAL` y el certificado hasta `ARCHIVED`; `DeleteCA` devuelve 409 mientras la configuración está `ACTIVE`. Sin estado de borrados pendientes (§4, §9).

Decisiones mías, abiertas a revisión:
- Una CA en `certificateHold` no se puede borrar hasta revocarla definitivamente (§5, §9).
- Solo se guarda el SKI de las CAs migradas (`legacy_ski`), no el de las nuevas (§4).
- Principios de compatibilidad con CAs de varios certificados (§1.3), a petición del usuario de no comprometer el futuro.
- Reconciliación en el job de monitorización del VA (§5).
- Al revocar una subordinada se regenera la CRL de la CA emisora (§5).
- Los roles huérfanos se conservan como `ARCHIVED` con un `ca_id` sintético (§6).
- Generación obligatoria de UUIDv7 en el backend; IDs de entrada ignorados; `url.PathEscape` para los existentes y detección de colisiones históricas en la migración (§7).
- Sin `POST` y sin endpoint para forzar regeneración (§8.1).

## 11. Puntos débiles y riesgos

Ordenados por impacto.

1. **La migración puede bloquear la actualización por varios motivos**: un SKI con más de una CA (la comprobación de la suposición), un firmante sin clave, o un ID de CA que contiene `/` o colisiona con un SKI antiguo. Cada fallo tiene que listar las filas afectadas e ir acompañado de un procedimiento manual documentado.
2. **`DeleteCA` depende del VA.**
   - Si el VA está caído o retrasado, `DeleteCA` devuelve 409 hasta que procese la revocación o la caducidad de la CA.
   - Si se retira el VA de una instalación, o se desactiva su suscriptor, con configuraciones todavía `ACTIVE`, esas CAs no se podrán borrar nunca. Este diseño no incluye una vía de administración para forzar `FINAL`. Se podría añadir más adelante, por ejemplo `POST /v1/crl-settings/{ca-id}/finalize`.
   - La reconciliación del job del VA ayuda si se pierden eventos, pero solo si el VA está en marcha.
3. **Acoplamiento entre servicios en la base de datos.** La migración del VA añade restricciones sobre `ca.certificates` y hacia ella, y el `ON UPDATE CASCADE` permite que operaciones del CA cambien filas del VA sin ningún evento. Mover la clave de un firmante a otro motor actualiza `crl_settings` sin avisar. Además, el servicio CA tiene que reconocer la violación del `CHECK` del VA para devolver su 409. Es aceptable, pero es una dependencia oculta que debe conocer quien toque `ca.certificates` o `DeleteCA`.
4. **Las CAs caducadas nunca tienen CRL final**, por diseño. Solo importa para verificadores que miran únicamente la CRL del certificado hoja y no la cadena.
5. **Cambio incompatible de API.** Afecta al SDK, a la UI (repositorio aparte) y a cualquier automatización que llame a `/v1/roles/:ca-ski`.
6. **El IDP con varias URLs** no está probado con verificadores reales. El `x509` de Go ignora el IDP; OpenSSL lo comprueba. Hace falta una prueba de interoperabilidad (OpenSSL `-crl_check` con el CDP antiguo y el nuevo) antes de publicar.
7. **CRLs finales de larga duración.** `nextUpdate` = el `notAfter` de la CA puede ser de muchos años en una raíz. Algunos clientes pueden rechazar o recortar valores de `nextUpdate` tan largos. Es la práctica aceptada para una CRL final, pero aquí no está probada.
8. **La reconciliación llama al servicio CA una vez por configuración en cada ejecución.** Con muchas CAs, añade carga al job. Si hace falta, se puede limitar a las configuraciones cuya última comprobación supere un umbral.
9. **Todos los escritores deben usar los métodos acotados del repositorio.** Cualquier guardado de fila entera que quede sobre `crl_settings` sobrescribiría `status` y el firmante, y reintroduciría #842. El repositorio no debe exponer un `Update` genérico.
10. **La purga y la retención del bucket no están definidas.** Los ficheros de CRL archivados se quedan en el bucket indefinidamente.
11. **Las CAs importadas siguen sin configuración de CRL.** No cambia, pero ahora es fácil de añadir, porque las configuraciones van por ID de CA.
12. **Bug preexistente encontrado en la revisión, fuera de alcance:** un `DeleteCA` en cascada nunca borra los certificados emitidos. `handleCascadeOperations` se ejecuta antes de borrar la fila de la CA, y `DeleteCertificate` rechaza el borrado mientras la CA emisora existe (`ErrCertificateIssuerCAExists`). `deleteCertificatesIssuedByCA` solo registra ese error en el log. Hay que abrir un issue aparte.

## 12. Reparto en PRs

| PR | Contenido | Por qué |
|---|---|---|
| **1. ID de CA y `CRLSettings`** | Modelo, migración (§6, sin las dos FKs ni el `CHECK` por estado), URLs/CDP/IDP, renombrado de API/SDK/OpenAPI/authz, enrutado por ID en los handlers, métodos acotados del repositorio con CAS, columna `status` (`ACTIVE`, y `ARCHIVED` para los huérfanos), 409 en el `PUT` si no está `ACTIVE`. | Es el único cambio incompatible. Por sí solo ya resuelve las claves compartidas para todo lo que se emita a partir de ahí. |
| **2. Ciclo de vida y protección** | Handlers de `FINAL`/`ARCHIVED`, CRL final, CRL de la emisora al revocar una subordinada, reconciliación en el job, `CalculateCRL` independiente de la fila de la CA, las dos FKs y el `CHECK` por estado, la comprobación y el 409 en `DeleteCA`. | **Las restricciones, el handler de `FINAL` y la comprobación de `DeleteCA` tienen que ir juntos.** Sin el handler de `FINAL`, todos los `DeleteCA` darían 409. La reconciliación tiene que salir antes que la versión del PR 1, o a la vez, para que las CAs ya revocadas reciban su CRL final. |
| **3. Endurecimiento** | `ImportCA` rechaza SKIs que colisionen; #815 se arregla en `ImportCA` (no borrando la fila en `DeleteCA`, que chocaría con la FK); firmantes delegados (#834). | Independiente. |

## 13. Pruebas

- **Tests de migración** (`engines/storage/postgres/migrations_test`): el mapeo 1:1, la comprobación de la suposición, los huérfanos (incluida una subordinada, cuyo ID de emisor es el del padre), los firmantes sin clave, la unicidad de `legacy_ski` y la continuidad de la numeración de CRL.
- **Tests del repositorio:**
  - la matriz FK/`CHECK` de §4 (borrar, soltar la clave, mover la clave, renombrar, guardar la fila entera) para `ACTIVE`, `FINAL` y `ARCHIVED`;
  - conflictos de CAS en la última CRL y en las transiciones de estado;
  - el estado nunca retrocede.
- **Tests del ensamblador del VA** (`backend/pkg/assemblers/tests/va`):
  - dos CAs sobre la misma clave tienen dos configuraciones y dos CRLs, cada una con solo sus propias revocaciones;
  - la URL antigua sirve la CRL de la CA migrada;
  - el IDP contiene las dos URLs;
  - el ciclo de vida: revocar → CRL final, después `FINAL` con las columnas de clave del firmante a `NULL`; borrar → `ARCHIVED`;
  - caducidad → `FINAL` sin CRL;
  - una CA en `certificateHold` sigue `ACTIVE`;
  - la reconciliación pasa a `FINAL`, con su CRL final, una configuración cuya CA ya está revocada.
- **Tests del CA:**
  - `DeleteCA` devuelve 409 mientras la configuración está `ACTIVE` y no cambia nada: ni revocaciones en cascada, y la fila de la CA y la clave siguen ahí;
  - lo mismo para una CA en `certificateHold`, con el mensaje de "revócala definitivamente primero";
  - una vez `FINAL`, `DeleteCA` funciona y borra la clave, salvo que otra CA la comparta;
  - borrar el certificado firmante devuelve 409 hasta que la configuración está `ARCHIVED`;
  - una CA sin configuración se borra como hoy.
- **Interoperabilidad:** `openssl verify -crl_check` con un certificado que lleva el CDP antiguo y otro que lleva el nuevo, contra la misma CRL.

### Revisión de seguridad del cambio de generación de CA ID (2026-11-12)

STRIDE: suplantación y manipulación se reducen al impedir elegir o reutilizar el ID; repudio se cubre publicando el ID real del resultado en el subject del evento. Divulgación, denegación de servicio y elevación de privilegios no añaden rutas nuevas; se conservan validación, autorización y restricciones de duplicados de certificados. UUIDv7 no es un secreto ni sustituye autorización.

DREAD (1–10, valoración de este cambio): daño 4, reproducibilidad 2, explotabilidad 2, usuarios afectados 3, descubribilidad 3; media 2,8. Riesgo principal: consumidores o fixtures que sigan utilizando el ID solicitado. Mitigación: usar el ID de respuesta en referencias, CDP y eventos; tests de UUIDv7 único en creación/importación y JSON antiguo con `id` de texto, numérico u objeto. La restauración conserva identidades mediante el mecanismo de backup, no mediante `ImportCA`.
