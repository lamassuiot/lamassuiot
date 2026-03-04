# Plan: CMP RA Protocol Implementation

The library `zjj/gocmpm` does not exist — the correct import is `github.com/zjj/gocmp`. This is a low-level ASN.1 CMP message codec only; there are no server-side request parsers, no HTTP server, and no callback framework. All server-side request parsing, dispatch, and response assembly must be written manually. The implementation reuses the existing `ESTService` methods (embedded in `DMSManagerService`) to perform the actual issuance: IR → `Enroll`, CR/KUR → `Reenroll`. The DMS is selected via the path segment `/.well-known/cmp/p/<dms-id>` on the single CMP endpoint, conforming to RFC 9480 §3.3. Full certConf/pkiConf requires two additional custom ASN.1 structs not provided by `gocmp`. An in-memory pending-transaction store (keyed by transactionID) bridges the CP response and the certConf confirmation.

> **Standards basis:** This plan targets CMP as defined in [RFC 4210], updated by [RFC 9480] (CMP Updates, November 2023), with algorithm guidance from [RFC 9481] (CMP Algorithms, November 2023). RFC 9480 introduces CMP version 3 (`cmp2021`/pvno=3), deprecates `EncryptedValue` in favour of `EnvelopedData`, adds the optional `hashAlg` field to `CertStatus`, and registers the `/.well-known/cmp` HTTP path. RFC 9481 updates the mandatory algorithm profile (Appendix D.2 of RFC 4210): mandatory MSG_SIG_ALG is RSA/SHA-256-2048; preferred MSG_MAC_ALG is PBMAC1 (over the legacy PasswordBasedMac); minimum digest is SHA-256.

## Steps

### 1. Add dependency
From `backend/`, run `go get github.com/zjj/gocmp` then `go work sync` at the workspace root. This adds `gocmp` and its transitive deps (`gmsm`, `golibkit`) to `backend/go.mod`.

### 2. Add CMP enrollment protocol enum
In `core/pkg/models/dms.go`, add the constant `CMP_RFC4210 EnrollmentProto = "CMP_RFC4210"` alongside the existing `EST_RFC7030` value.

### 3. Create custom ASN.1 CMP types
Create `backend/pkg/controllers/cmp_asn1.go` defining the raw structures needed for server-side parsing and the unimplemented body types:
- `RawPKIMessage` — mirrors `PKIMessage` using `asn1.RawValue` for the body field (needed to extract the body tag without a CHOICE parser)
- `CertReqMessages` — `[]CertReqMessage` (sequence of gocmp's `CertReqMessage`)
- `CertStatusASN1` — per [RFC 9480 §2.10], the updated structure is:
  ```
  CertStatus ::= SEQUENCE {
    certHash   OCTET STRING,
    certReqId  INTEGER,
    statusInfo PKIStatusInfo                                    OPTIONAL,
    hashAlg    [0] AlgorithmIdentifier{DIGEST-ALGORITHM, {...}} OPTIONAL
  }
  ```
  The `hashAlg` field SHOULD be present only when the certificate's `signatureAlgorithm` does not directly specify a hash algorithm (e.g., EdDSA — Ed25519 requires SHA-512, Ed448 requires SHAKE256(d=512) per [RFC 9481 §3.3]). For RSA and ECDSA with SHA-2, omit it and hash with the same digest as the cert signature.
- `CertConfContent` — `[]CertStatusASN1`
- `PKIConfContent` — `asn1.RawValue` encoding a NULL (for pkiConf body, tag 19)
- Constants for body tags: `tagIR=0`, `tagCR=2`, `tagCP=3`, `tagKUR=4`, `tagKUP=8`, `tagCertConf=24`, `tagPKIConf=19`
- Constant `pvnoCMP2000 = 2` — servers MUST default to `cmp2000` (pvno=2) per [RFC 9480 §2.20]; use `cmp2021` (pvno=3) only when EnvelopedData or `hashAlg` is needed

### 4. Create transaction store
Inside `backend/pkg/controllers/cmp.go`, define an in-memory `cmpTxStore` type backed by `sync.Map`:
- Key: hex-encoded transactionID byte slice
- Value: `pendingTx { CAID string; SerialNumber string; CertDER []byte; SentAt time.Time }`
- Add a periodic cleanup goroutine (5-minute TTL) started once at handler construction

### 5. Create CMP controller
`backend/pkg/controllers/cmp.go`:
- Struct `cmpHttpRoutes` holding `svc services.DMSManagerService`, `logger`, and `*cmpTxStore`
- Constructor `NewCMPHttpRoutes(logger, svc)` returning the struct
- Single `HandleCMP(ctx *gin.Context)` method handling all operations:
  a. Read raw body bytes (`io.ReadAll`), content-type must be `application/pkixcmp`
  b. `asn1.Unmarshal` into `RawPKIMessage` to get the header and raw body tag
  c. Extract `transactionID` from `Header.TransactionID` (used for correlation and certConf)
  d. Extract DMS ID from the `:id` path parameter (Gin route `/.well-known/cmp/p/:id`); return `pkiError` if empty
  e. Dispatch on raw body tag:
     - **tag 0 (IR) / tag 2 (CR)**: unmarshal body bytes into `CertReqMessages`; for each request, extract the embedded SubjectPublicKeyInfo DER from `CertTemplate.PublicKey`; synthesize a `*x509.CertificateRequest` using `x509.CreateCertificateRequest` with the template's subject/SANs and the public key; verify the CSR self-signature for POPO; call `svc.Enroll` (IR) or `svc.Reenroll` (CR) with `aps=dmsID`; build CP response body using `gocmp` response types; store `pendingTx` keyed by transactionID; serialize and return DER
     - **tag 4 (KUR)**: same flow as CR but calls `svc.Reenroll`; respond with KUP (tag 8)
     - **tag 24 (certConf)**: unmarshal body into `CertConfContent`; look up `pendingTx` by transactionID; compute `certHash` as SHA-256 of stored cert DER (or the hash algorithm from the cert's `signatureAlgorithm` per [RFC 9481 §2]; for EdDSA certs, use SHA-512 for Ed25519 and SHAKE256(d=512) for Ed448 and include the `hashAlg` field); verify `CertHash` matches; delete transaction from store; respond with pkiConf (tag 19)
     - **unknown tag**: return CMP error message with `PKIStatus=rejection`
  f. **CSR synthesis note**: since gocmp's `CertTemplate` holds a raw `SubjectPublicKeyInfo` (not a `crypto.PublicKey`), parse the public key first with `x509.ParsePKIXPublicKey`, then build a stub `*x509.CertificateRequest` manually (set `PublicKey`, `Subject`, `DNSNames`, `IPAddresses` from template fields) and call `x509.CreateCertificateRequest` with a throwaway signer — or simpler, just build an unsigned CSR struct and let the DMS service validate the POPO separately.
  g. **gmsm conversion note**: any `*gmsm/x509.Certificate` received (e.g., inside `CertWithEncValue`) must be re-parsed with `stdlib_x509.ParseCertificate(gmsmCert.Raw)` before use.

### 6. Error helper
Add `buildPKIError(header *cmp.PKIHeader, status cmp.PKIStatus, reason string) []byte` that constructs a CMP Error body and serializes it to DER for error responses.

### 7. Create CMP routes
`backend/pkg/routes/cmp.go`:
- `NewCMPHTTPLayer(logger, rg *gin.RouterGroup, svc services.DMSManagerService)` registering:
  ```
  POST /.well-known/cmp/p/:id   → cmpRoutes.HandleCMP
  ```
- Content-type validation middleware: reject non-`application/pkixcmp` requests with HTTP 415
- **RFC 9480 §3.3 compliance:** RFC 9480 registers `/.well-known/cmp` as the standard base path, with `/p/<name>` used to differentiate CA/profile names. Using `/.well-known/cmp/p/:id` (where `:id` is the DMS ID) satisfies the standard URI structure and maximises interoperability with off-the-shelf CMP clients (e.g., `openssl cmp`, `cmclient`).

### 8. Wire into DMS assembler
In `backend/pkg/routes/dmsmanager.go`, call `NewCMPHTTPLayer(logger, httpGrp, svc)` alongside the existing `NewDMSManagerHTTPLayer` call. No changes to the assembler Go file are needed since services are already threaded through the routes layer.

### 9. Module hygiene
After code is written, run `go mod tidy` in `backend/` and `go work sync` at workspace root to ensure the `gocmp` dependency is correctly recorded.

## Verification

- Unit test `backend/pkg/controllers/cmp_test.go`: craft raw DER IR/CR/KUR/certConf messages using `gocmp` builder functions, POST to `/.well-known/cmp/p/test-dms`, assert HTTP 200 with `application/pkixcmp` content-type, verify ASN.1-decoded response body tags (CP=3, KUP=8, pkiConf=19)
- Integration test using a real CMP client (e.g., `openssl cmp -cmd ir -server localhost:8085/.well-known/cmp/p/<dms-id>`) against a running monolithic instance
- Test error paths: missing `?id=`, unknown body tag, invalid POPO, stale transactionID in certConf

## Decisions

- Chose `/.well-known/cmp/p/<dms-id>` path segment over `?id=` query param — conforms to [RFC 9480 §3.3] well-known URI structure and is understood natively by standard CMP clients
- Chose full certConf/pkiConf (user preference; requires custom ASN.1 structs not in `gocmp`)
- POPO validation via CSR self-signature verification (using stdlib `x509.CheckSignature`)
- No MAC-based protection (PBMAC1) in scope — [RFC 9481 §7.1] mandates PBMAC1 as preferred MAC but this is a future concern
- IR and CR are handled identically (both route to `svc.Enroll`/`svc.Reenroll`) since the DMS service already encodes enrollment policy
- certConf uses in-memory transaction store (acceptable since CMP confirm is milliseconds; no persistence needed across restarts)
- pvno set to `cmp2000` (2) on all server responses per [RFC 9480 §2.20] version-negotiation rule; upgrade to `cmp2021` (3) deferred until EnvelopedData transport or EdDSA certConf is needed
- `EncryptedValue` usage avoided throughout; if server-side key generation is ever added, use `EnvelopedData` in `CertifiedKeyPair` per [RFC 9480 §2.7] (EncryptedValue is deprecated)
- certHash algorithm defaults to SHA-256; EdDSA special-casing (SHA-512 / SHAKE256) tracked as a follow-on item per [RFC 9481 §3.3]
- HTTP path `/.well-known/cmp/p/<dms-id>` adopted; conforms to [RFC 9480 §3.3] and [RFC 8615] well-known URI registration

## References

| RFC | Title | Relevance |
|-----|-------|-----------|
| [RFC 4210](https://www.rfc-editor.org/rfc/rfc4210) | Internet X.509 PKI Certificate Management Protocol (CMP) | Core protocol: message formats, body types, transaction flow |
| [RFC 4211](https://www.rfc-editor.org/rfc/rfc4211) | Certificate Request Message Format (CRMF) | CertReqMessages, CertTemplate, POPO structures |
| [RFC 6712](https://www.rfc-editor.org/rfc/rfc6712) | HTTP Transfer for CMP | HTTP transport binding (content-type `application/pkixcmp`) |
| [RFC 9480](https://www.rfc-editor.org/rfc/rfc9480) | Certificate Management Protocol (CMP) Updates | **Updates RFC 4210 & 6712:** CMP v3 (`cmp2021`), EnvelopedData replaces EncryptedValue, `hashAlg` in CertStatus, `/.well-known/cmp` URI, extended polling, new genm/genp types |
| [RFC 9481](https://www.rfc-editor.org/rfc/rfc9481) | Certificate Management Protocol (CMP) Algorithms | **Updates RFC 4210 Appendix D.2:** mandatory RSA/SHA-256, preferred PBMAC1 over PasswordBasedMac, ECDSA/EdDSA guidance, certHash algorithm per cert signature type |
| [RFC 9483](https://www.rfc-editor.org/rfc/rfc9483) | Lightweight CMP Profile | Informational: IoT enrollment operations; aligns with Lamassu's target use case |
