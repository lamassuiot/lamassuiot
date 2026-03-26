# PRD: Lightweight CMP (RFC 9483) Full Implementation in DMS Manager

## Problem Statement

The DMS Manager acts as a Registration Authority (RA) for IoT and industrial devices. It already provides full certificate lifecycle management via EST (RFC 7030) — including enrollment, re-enrollment, server-side key generation, and CA certificate distribution. A partial CMP implementation exists, covering the basic enrollment and re-enrollment flows (ir/cr → ip/cp, kur → kup) and certificate confirmation (certConf → pkiConf). However, the implementation is incomplete in several critical areas:

- Several protocol operations defined by RFC 9483 are not dispatched: revocation (rr/rp), PKCS#10-wrapped enrollment (p10cr), support messages (genm/genp for caCerts, rootCaCertUpdate, certReqTemplate, crlStatusList), and central key generation (CKG).
- The server does not validate the EE's signature-based protection on incoming requests, making the RA unable to authenticate requests cryptographically.
- Response `extraCerts` are not populated with the RA's protection certificate chain, which means EE clients cannot verify the RA's response signature.
- The CMP controller does not enforce the DMS's configured authentication settings (mTLS validation CAs), unlike the EST controller which enforces these via middleware.
- There is no configurable policy for how CertTemplate extensions (SANs, key usage, EKU, etc.) are handled: the current implementation silently drops all extensions, using only Subject and public key.
- The `LWCGetRootCACertUpdate`, `LWCGetCertReqTemplate`, and `LWCGetCRL` service methods are stubs that always return nil.
- Central key generation, which EST supports via `ServerKeyGen`, has no CMP equivalent, creating a feature gap for devices unable to generate keys locally.

As a result, devices using standard CMP clients (such as `openssl cmp`) against the DMS Manager experience incomplete protocol coverage, inability to revoke certificates via CMP, and interoperability failures when response protection validation is required.

## Solution

Complete the RFC 9483 Lightweight CMP Profile implementation in the DMS Manager, bringing it to full protocol parity with the existing EST implementation. This includes:

1. Dispatching all remaining RFC 9483 protocol operations in the CMP HTTP controller.
2. Enforcing DMS-configured mTLS authentication on incoming CMP requests.
3. Validating signature-based protection on EE requests.
4. Populating `extraCerts` with the RA's protection certificate chain in all responses.
5. Implementing a configurable "Enforce Issuance Profile" policy on `EnrollmentOptionsLWCRFC9483` that governs whether CertTemplate extensions are forwarded to the CA or overridden by the DMS issuance profile.
6. Fully implementing the `LWCGetRootCACertUpdate`, `LWCGetCertReqTemplate`, and `LWCGetCRL` service methods.
7. Adding central key generation (CKG) via `EnvelopedData` with Key Transport (RSA-OAEP) and Key Agreement (ECDH), validating the EE's encryption certificate against a DMS-configured trusted CA.
8. Writing both unit tests (controller-level, mocked service) and E2E tests using `openssl cmp` mirroring the existing EST test structure.

Delayed delivery / polling (pollReq/pollRep async) and MAC-based protection (PBMAC1) are explicitly out of scope for this iteration.

## User Stories

### Enrollment

1. As an IoT device operator, I want my device to send a CMP Initialization Request (ir) to the DMS Manager and receive a signed certificate in the response (ip), so that the device can obtain its operational identity certificate automatically.
2. As an IoT device operator, I want my device to send a CMP Certificate Request (cr) to the DMS Manager and receive a signed certificate in the response (cp), so that the device can request a certificate when it already belongs to the PKI.
3. As an IoT device operator, I want my device to send a PKCS#10 certificate request wrapped in a CMP p10cr message and receive a certificate in the cp response, so that I can use standard PKCS#10 tooling in devices that support CMP transport but generate CSRs in PKCS#10 format.
4. As an IoT device operator, I want my device to receive an ip/cp response that includes the RA's protection certificate chain in `extraCerts`, so that the device can verify the RA's signature on the response without pre-configuring the RA's certificate.
5. As a PKI administrator, I want the DMS Manager to validate the EE's signature-based protection on incoming ir/cr/kur/p10cr messages, so that unauthenticated or tampered requests are rejected before issuance.
6. As a PKI administrator, I want the DMS Manager to enforce mTLS authentication on incoming CMP requests using the bootstrap CAs configured on the DMS, so that only authorized devices can enroll.
7. As a PKI administrator, I want the DMS to support Just-In-Time Provisioning (JITP) for CMP enrollment, so that devices that present a valid IDevID certificate are automatically registered in the device manager on first enrollment.
8. As a PKI administrator, I want the DMS to support pre-registration mode for CMP enrollment, so that only explicitly registered devices can obtain operational certificates.
9. As a PKI administrator, I want to configure the DMS to use a separate enrollment CA specifically for CMP-enrolled devices (overriding the default enrollment CA), so that CMP-enrolled and EST-enrolled devices can have their certificates from different CA hierarchies.

### Certificate Confirmation

10. As an IoT device operator, I want my device to send a certConf message after receiving a certificate, so that the RA knows the device successfully received and accepted the certificate.
11. As an IoT device operator, I want the DMS Manager to respond with pkiConf after verifying certHash, so that my device knows the confirmation was received and the transaction is complete.
12. As a PKI administrator, I want to configure the DMS to require explicit certificate confirmation (EXPLICIT mode), so that certificates are only considered active after the device confirms receipt.
13. As a PKI administrator, I want to configure the DMS to use implicit confirmation (IMPLICIT mode), so that constrained devices that cannot send certConf do not need to.
14. As a PKI administrator, I want the DMS to honor the `id-it-implicitConfirm` OID in the EE request's `generalInfo` header when the DMS is configured for IMPLICIT mode, so that EEs can skip certConf per RFC 9483 §4.1.1.

### Re-enrollment

15. As an IoT device operator, I want my device to send a Key Update Request (kur) to the DMS Manager and receive a renewed certificate in the kup response, so that the device can renew its certificate before expiry.
16. As a PKI administrator, I want the DMS to revoke the previous certificate when a kur is processed and `RevokeOnReEnrollment` is configured, so that superseded certificates are invalidated.
17. As a PKI administrator, I want the DMS to enforce re-enrollment window policies (delta before expiry) for CMP kur, consistent with the EST re-enrollment settings.

### Revocation

18. As an IoT device operator, I want my device to send a Revocation Request (rr) to the DMS Manager specifying a revocation reason, so that a compromised or decommissioned certificate can be revoked via CMP.
19. As an IoT device operator, I want my device to receive a Revocation Response (rp) confirming the revocation status, so that the device knows the revocation was processed.
20. As a PKI administrator, I want the DMS to validate that the certificate being revoked belongs to the correct DMS before processing the revocation, so that cross-DMS revocation attempts are rejected.

### Support Messages (genm/genp)

21. As an IoT device operator, I want my device to send a `genm` message with InfoType `id-it-caCerts` and receive a `genp` response containing the enrollment CA certificate chain, so that the device can obtain the trust anchors it needs to validate its issued certificate.
22. As an IoT device operator, I want my device to send a `genm` message with InfoType `id-it-rootCaKeyUpdate` and receive a `genp` response containing the new and old root CA certificates, so that the device can update its trust anchor when the root CA is renewed.
23. As an IoT device operator, I want my device to send a `genm` message with InfoType `id-it-certReqTemplate` and receive a `genp` response describing what the CA requires in certificate requests, so that the device can build conformant certificate requests.
24. As an IoT device operator, I want my device to send a `genm` message with InfoType `id-it-crlStatusList` and receive a `genp` response containing the latest CRL for the enrollment CA, so that the device can perform local revocation checking.
25. As a PKI administrator, I want the `genm/caCerts` response to reflect the same CA distribution settings as EST (IncludeLamassuSystemCA, IncludeEnrollmentCA, ManagedCAs), so that devices using CMP get the same trust bundle as devices using EST.

### Central Key Generation

26. As an IoT device operator, I want my device to request a certificate by sending an ir/cr with an empty public key field, indicating that the RA should generate the key pair, so that constrained devices without an on-board key generator can still obtain operational certificates.
27. As an IoT device operator, I want the private key generated by the RA to be returned to my device encrypted inside the ip/cp response using `EnvelopedData` with Key Transport (RSA-OAEP) for RSA encryption keys, so that the key is delivered securely.
28. As an IoT device operator, I want the private key generated by the RA to be returned to my device encrypted inside the ip/cp response using `EnvelopedData` with Key Agreement (ECDH) for ECDSA/EC encryption keys, so that the key is delivered securely.
29. As a PKI administrator, I want to configure on the DMS whether central key generation is permitted at all, so that I can enforce device-side key generation where required by policy.
30. As a PKI administrator, I want the DMS to validate the EE's encryption certificate (used to wrap the generated key) against a DMS-configured trusted CA, so that only authorized devices can receive server-generated keys.
31. As a PKI administrator, I want the DMS to generate server-side keys using the KMS service (not in-process), consistent with how EST ServerKeyGen works, so that generated private keys are never exposed in application memory.

### Authentication and Protection

32. As a PKI administrator, I want the DMS Manager to enforce mTLS authentication for CMP requests, validating the EE's TLS client certificate against the bootstrap CAs configured in `AuthOptionsMTLS.ValidationCAs`, so that only authorized devices can use the CMP endpoint.
33. As a PKI administrator, I want the DMS to support an `ALLOW_EXPIRED` flag on mTLS validation for CMP, so that devices with expired IDevID certificates can still re-enroll during a grace period, consistent with EST behavior.
34. As a PKI administrator, I want the DMS Manager to verify the EE's signature-based CMP message protection on all incoming request messages (ir, cr, kur, p10cr, rr, genm, certConf), so that tampered or forged CMP messages are rejected.
35. As a PKI administrator, I want the DMS Manager to sign all CMP response messages using the protection certificate configured on the DMS (`ProtectionCertificateSerialNumber`), so that EE clients can verify response authenticity.
36. As a PKI administrator, I want all protected CMP responses to include the RA's full certificate chain in `extraCerts`, so that EE clients that have not pre-configured the RA certificate can still verify the response signature.
37. As a PKI administrator, I want to leave `ProtectionCertificateSerialNumber` empty to send unprotected CMP responses, so that I can operate in environments that do not require RA-signed responses.

### DMS Configuration

38. As a PKI administrator, I want to configure the DMS with `EnforceIssuanceProfile = true` so that the issuance profile defined on the DMS fully governs certificate contents, regardless of what extensions the EE requests in the CertTemplate.
39. As a PKI administrator, I want to configure the DMS with `EnforceIssuanceProfile = false` so that SANs, key usage, and EKU extensions present in the EE's CertTemplate are forwarded to the CA as part of the certificate request.
40. As a PKI administrator, I want to configure `ServerKeyGenEnabled = true` on the DMS to allow EEs to request central key generation, and `false` to reject such requests, so that I can enforce device-side key generation policy per DMS.
41. As a PKI administrator, I want to configure `CKGTrustedEncryptionCAs` on the DMS — a list of CA IDs whose issued certificates are accepted as EE encryption certificates for central key generation — so that only devices with trusted encryption credentials can receive server-generated keys.
42. As a PKI administrator, I want to configure a `ConfirmationTimeout` on the DMS specifying how long the server waits for a certConf after issuing a certificate in EXPLICIT mode, after which the pending transaction is evicted, so that stale transactions do not consume server resources indefinitely.

### Observability and Error Handling

43. As a PKI administrator, I want CMP request errors (malformed ASN.1, unsupported body tag, auth failure, signature verification failure) to be returned as a properly formatted CMP error body (`error` tag 23) with a descriptive `PKIFreeText` string, so that CMP clients can display actionable error messages.
44. As a PKI administrator, I want enrollment, re-enrollment, revocation, and CKG operations via CMP to generate the same audit events (device provisioned, re-provisioned, renewed, revoked) as equivalent EST operations, so that device lifecycle tracking is consistent regardless of enrollment protocol.
45. As a PKI administrator, I want CMP handler errors to be logged at the appropriate level (WARN for client errors, ERROR for server errors) with the transactionID, DMS ID, and body tag included, so that I can correlate logs with specific CMP transactions.

### Interoperability

46. As a PKI administrator, I want the DMS Manager's CMP endpoint to be compatible with `openssl cmp` command-line client (supporting ir, cr, kur, p10cr, rr, genm subcommands), so that I can test and operate the RA using a widely available standard CMP client.
47. As a PKI administrator, I want the CMP endpoint path to follow RFC 9480 §3.3 (`/.well-known/cmp/p/<dms-id>`), so that standard CMP clients can be pointed at it without custom path configuration.
48. As a PKI administrator, I want the CMP endpoint to reject requests with a Content-Type other than `application/pkixcmp` with HTTP 415, so that accidental non-CMP traffic is rejected at the HTTP layer.
49. As a PKI administrator, I want the CMP pvno in all responses to be set to `cmp2000` (2) per RFC 9480 §2.20, so that the server remains compatible with both CMP v2 and CMP v3 clients.

## Implementation Decisions

### HTTP Controller (`backend/pkg/controllers/cmp.go`)

- Add dispatch cases for all currently unhandled body tags:
  - Tag 4 (`p10cr`): parse the embedded PKCS#10 CSR directly, verify its self-signature, call `LWCEnroll`.
  - Tag 11 (`rr`): parse `RevReqContent`, call `LWCRevokeCertificate` for each entry, build `rp` (tag 12) response.
  - Tag 21 (`genm`): parse `GenMsgContent` sequence of `InfoTypeAndValue`; sub-dispatch on InfoType OID to the corresponding service method.
- For `genm` sub-dispatch, support the following InfoType OIDs:
  - `id-it-caCerts` (1.3.6.1.5.5.7.4.17) → `LWCCACerts`
  - `id-it-rootCaKeyUpdate` (1.3.6.1.5.5.7.4.20) → `LWCGetRootCACertUpdate`
  - `id-it-certReqTemplate` (1.3.6.1.5.5.7.4.19) → `LWCGetCertReqTemplate`
  - `id-it-crlStatusList` (1.3.6.1.5.5.7.4.22) → `LWCGetCRL`
- Add auth enforcement middleware (parallel to EST's `clientCertMiddleware`): extract the mTLS client certificate from the Gin TLS connection context, validate it against the DMS's `AuthOptionsMTLS.ValidationCAs`, reject with CMP error if validation fails.
- Add signature-based protection validation: after parsing the PKIHeader, if a protection algorithm is present and the protection value is populated, verify the EE's signature using the certificate in `extraCerts[0]` (the EE's signing cert as per RFC 9483 §3.2).
- Add `implicitConfirm` generalInfo header check: if the request contains `id-it-implicitConfirm` OID in `generalInfo` and the DMS is configured with `IMPLICIT` confirmation mode, skip storing the pending transaction and do not expect certConf.
- Populate `extraCerts` in all protected responses by calling a helper that fetches the RA protection certificate's full chain from the CA service.
- For CKG: detect empty public key in CertTemplate (ir/cr); extract the EE's encryption certificate from `extraCerts` in the request; call `LWCServerKeyGen`; wrap the private key in `EnvelopedData` using the appropriate key management technique based on the EE encryption certificate's key type.

### ASN.1 Structures (`backend/pkg/controllers/cmp_asn1.go`)

- Add structures for: `RevReqContent` (rr body), `RevRepContent` (rp body), `GenMsgContent` / `GenRepContent` (genm/genp bodies as sequences of `InfoTypeAndValue`), `InfoTypeAndValue`.
- Add CKG-related structures: `EnvelopedData` wrapper, `KeyTransRecipientInfo` (RSA-OAEP), `KeyAgreeRecipientInfo` (ECDH).
- Add InfoType OID constants for all four genm/genp operations.
- Add body tag constants for: `cmpBodyTagRR = 11`, `cmpBodyTagRP = 12`, `cmpBodyTagGenM = 21`, `cmpBodyTagGenP = 22`, `cmpBodyTagPollReq = 25`, `cmpBodyTagPollRep = 26` (stubs for future use).

### Protection Layer (`backend/pkg/controllers/cmp_protection.go`)

- Add `verifyRequestProtection(rawMsg, extraCerts)` function: parse the protection algorithm from the PKIHeader, verify the protection value over `DER(header) || DER(body)` using the public key from the EE's protection certificate.
- Extend `marshalProtectedResponse` to accept a certificate chain and populate the `extraCerts` field of the PKIMessage.
- Add `fetchProtectionChain(aps string)` helper that retrieves the RA's protection certificate and its issuing chain from the CA service.

### Service Interface (`core/pkg/services/lwcmp.go`)

- Add `LWCServerKeyGen(ctx, csr, aps string, eeEncCert *x509.Certificate) (*x509.Certificate, []byte, error)` where the `[]byte` return is the DER-encoded `EnvelopedData` containing the generated private key — keeping the private key material outside Go memory as much as possible by delegating generation to the KMS service.
- The key management technique (Key Transport vs. Key Agreement) is selected by the service based on the EE encryption certificate's public key algorithm; the interface is algorithm-agnostic to support future extension.

### Service Implementation (`backend/pkg/services/dmsmanager_lwcmp.go`)

- Implement `LWCServerKeyGen`: validate EE encryption cert against `CKGTrustedEncryptionCAs`; generate key pair in KMS; issue certificate via `caClient.SignCertificate`; export private key from KMS; wrap in `EnvelopedData` using the appropriate key management technique; bind certificate to device.
- Implement `LWCGetRootCACertUpdate`: fetch root CA certificate chain from `caClient`; return `RootCACertUpdateOutput` with `NewWithNew` and `NewWithOld`; return nil if no update is available.
- Implement `LWCGetCertReqTemplate`: read the DMS's issuance profile; serialize the profile constraints (allowed key algorithms, subject template) as `CertReqTemplateOutput`; return nil if no profile is configured.
- Implement `LWCGetCRL`: call the CA service's CRL endpoint for the DMS enrollment CA; return nil if no CRL newer than `CurrentThisUpdate` is available.
- Extend `LWCEnroll` and `LWCReenroll` to respect the `EnforceIssuanceProfile` flag: when false, extract extensions from the CertTemplate and append them to the `CertRequest` extensions before calling `caClient.SignCertificate`.

### Model Changes (`core/pkg/models/dms_lwcmp_options.go`)

- Add `EnforceIssuanceProfile bool` to `EnrollmentOptionsLWCRFC9483`: when `true`, the DMS issuance profile controls all certificate contents and CertTemplate extensions are ignored; when `false`, Subject + public key + extensions from the CertTemplate are forwarded to the CA.
- Add `ServerKeyGenEnabled bool` to `EnrollmentOptionsLWCRFC9483`: when `false` (default), CKG requests are rejected with a CMP error.
- Add `CKGTrustedEncryptionCAs []string` to `EnrollmentOptionsLWCRFC9483`: list of CA IDs whose certificates are accepted as EE encryption certificates for CKG. Required when `ServerKeyGenEnabled = true`.

### Audit Events

- CMP enrollment (ir/cr/p10cr successful) emits a `DeviceProvisioned` event.
- CMP re-enrollment (kur successful) emits a `DeviceRenewed` event.
- CMP revocation (rr successful) emits a `DeviceRevoked` event.
- CMP CKG (ir/cr with empty pubkey successful) emits a `DeviceProvisioned` event with a CKG metadata flag.
- These events follow the same structure and publisher pattern used by the EST service.

### Transaction Store

- The existing in-memory `cmpTxStore` (keyed by transactionID hex, 5-minute TTL) is retained for explicit certConf correlation.
- For CKG transactions, the stored `pendingTx` is extended to include the encrypted key bytes so that certConf can confirm delivery before those are discarded.
- Delayed delivery (async CA polling) is out of scope; the transaction store is not moved to persistent storage in this iteration.

### HTTP Routing (`backend/pkg/routes/cmp.go`)

- No new routes are needed; all RFC 9483 operations share the single `POST /.well-known/cmp/p/:id` endpoint.
- The auth enforcement middleware is added to this route group.

## Testing Decisions

### What makes a good test

Tests should verify externally observable behavior: the correct CMP body tag and content in the response for a given input message, the correct HTTP status code, and the correct device/certificate state in downstream services after an operation. Tests should not assert on internal struct layouts, intermediate ASN.1 encoding details, or logging output.

### Unit Tests (`backend/pkg/controllers/cmp_test.go`)

- One test per dispatched body tag: ir, cr, p10cr, kur, certConf, rr, genm/caCerts, genm/rootCaCertUpdate, genm/certReqTemplate, genm/crlStatusList.
- Use a mock `LightweightCMPService` to isolate the controller.
- Test error paths: missing DMS ID, malformed DER, unsupported body tag, certHash mismatch in certConf, protection validation failure, unknown genm InfoType OID.
- Test protection validation: valid EE signature accepted; invalid/missing signature rejected with CMP error body.
- Test `extraCerts` population: assert the response PKIMessage `extraCerts` field is non-empty when protection is enabled.
- Test CKG detection: empty public key in CertTemplate triggers `LWCServerKeyGen`; non-empty public key triggers `LWCEnroll`.
- Prior art: `backend/pkg/controllers/` existing handler tests.

### E2E Tests (`backend/pkg/assemblers/tests/dms-manager/cmp_e2e_test.go`)

- Mirror the EST E2E test structure: shared `cmpTestFixture`, `newCMPTestFixture(t)`, helper functions for CA creation and DMS creation.
- Use `openssl cmp` CLI as the external CMP client via `os/exec`, verifying real wire-format interoperability.
- Required test scenarios:
  - `TestCMPEnroll_IR_ImplicitConfirm`: ir with `id-it-implicitConfirm` in generalInfo, verify ip response and device created.
  - `TestCMPEnroll_IR_ExplicitConfirm`: ir followed by certConf, verify pkiConf response.
  - `TestCMPEnroll_CR`: cr followed by certConf, verify cp response.
  - `TestCMPEnroll_P10CR`: p10cr with a PKCS#10 CSR, verify cp response.
  - `TestCMPReenroll_KUR`: kur from a previously enrolled device, verify kup and device renewed.
  - `TestCMPRevoke_RR`: rr after enrollment, verify rp and certificate status is revoked.
  - `TestCMPGenM_CACerts`: genm with id-it-caCerts, verify genp contains enrollment CA cert chain.
  - `TestCMPGenM_RootCACertUpdate`: genm with id-it-rootCaKeyUpdate, verify genp.
  - `TestCMPGenM_CertReqTemplate`: genm with id-it-certReqTemplate, verify genp.
  - `TestCMPGenM_CRL`: genm with id-it-crlStatusList, verify genp contains a valid CRL.
  - `TestCMPServerKeyGen`: ir with empty public key field, verify ip contains `EnvelopedData` with generated private key.
  - `TestCMPEnroll_InvalidDMS`: request to unknown DMS ID returns CMP error body.
  - `TestCMPEnroll_RevokedBootstrapCert`: enrollment with a revoked IDevID cert fails auth.
  - `TestCMPEnroll_EnforceIssuanceProfile_True`: CertTemplate with SANs; when `EnforceIssuanceProfile=true`, issued cert does not contain those SANs.
  - `TestCMPEnroll_EnforceIssuanceProfile_False`: CertTemplate with SANs; when `EnforceIssuanceProfile=false`, issued cert contains those SANs.
- Prior art: `backend/pkg/assemblers/tests/dms-manager/cmp_e2e_test.go` (existing), `est_e2e_test.go`.

## Out of Scope

- **MAC-based protection (PBMAC1):** Authentication via shared secret / password-based message authentication code. Only signature-based protection (mTLS client certificate) is in scope. PBMAC1 may be addressed in a future iteration for bootstrap scenarios without IDevID certificates.
- **Delayed delivery / polling (pollReq / pollRep):** Asynchronous CA communication where the RA responds with `waiting` status and the EE polls. Not in scope because there is no async CA interaction in the current architecture.
- **Nested / batched messages (§5.2.2.2):** Batching of multiple CMP transactions in a single nested PKIMessage. Not applicable to EE-to-RA communication.
- **Announcement messages:** Push-model operations (caKeyUpdateAnn, certAnn, revAnnContent) that require a CMP server on the EE. All operations follow the pull model.
- **CoAP transport (RFC 9482):** Only HTTP transport over TLS is in scope.
- **CMP-to-upstream-CA forwarding:** The DMS Manager terminates CMP and uses internal Lamassu CA service APIs. Upstream CMP relay is not in scope.
- **BRSKI / SZTP integration:** Use of CMP within BRSKI-AE or SZTP provisioning workflows.

## Further Notes

- **Alignment with RFC 9480:** All responses use `pvno = cmp2000` (integer 2) per RFC 9480 §2.20. The `EnvelopedData` transport for CKG (RFC 9480 §2.7) replaces the deprecated `EncryptedValue`; `EncryptedValue` must not be used in any new code.
- **Algorithm guidance (RFC 9481):** The mandatory message signature algorithm is RSA/SHA-256 (2048-bit minimum). For ECDSA, SHA-256 with P-256 is the recommended minimum. The `certHash` in `certConf` defaults to SHA-256; for EdDSA certificates (Ed25519/Ed448), the `hashAlg` field in `CertStatus` must be populated per RFC 9481 §3.3 (SHA-512 for Ed25519, SHAKE256(d=512) for Ed448).
- **CKG extensibility:** The `LWCServerKeyGen` service interface is intentionally algorithm-agnostic. The controller selects the key management technique based on the EE encryption certificate's key type. Future support for additional techniques (e.g., Password-Based per RFC 9483 §4.1.6.3) can be added without changing the service interface.
- **Issuance profile enforcement vs. CertTemplate extension forwarding:** When `EnforceIssuanceProfile = false`, the extensions extracted from the CertTemplate are merged with any extensions already present in the DMS issuance profile. The issuance profile's validity period and key constraints always apply; the EE cannot override certificate lifetime via CertTemplate.
- **`VerifyCSRSignature` flag:** When the DMS is used with CMP, `VerifyCSRSignature` in `EnrollmentSettings` should be set to `false` because the synthetic PKCS#10 CSR constructed from the CertTemplate carries a dummy signature. The EE's proof-of-possession is instead validated at the CMP layer via the request protection verification.
- **Protection certificate lifecycle:** The RA protection certificate (`ProtectionCertificateSerialNumber`) is an end-entity certificate whose private key is managed by the KMS service. Operators must renew this certificate before expiry; no automatic renewal is provided by the DMS Manager.
- **openssl cmp compatibility:** Tests use `openssl cmp` (OpenSSL 3.x) as the reference client. The implementation should be validated against this client's default behavior, including its default protection algorithm selection and certConf handling.


==========

The PRD is in context from the previous step. I have a thorough understanding of the codebase. Let me identify the architectural      
  anchors and propose the vertical slices.                                                                                              
                                                                                                                                      
---                                                                                                                                   
Durable architectural decisions I identified                                                                                          
                                                                                                                                      
- Single route: POST /.well-known/cmp/p/:id handles all operations — no new routes needed                                             
- Dispatch model: Single HandleCMP function dispatching on ASN.1 body tag; genm sub-dispatches on InfoType OID                        
- Auth: mTLS enforced as Gin middleware on the CMP route group (mirrors EST pattern)                                                  
- Protection: Signature-based only (KMS-managed RA cert); no PBMAC1                                                                   
- Transaction store: In-memory cmpTxStore, stays in-memory (no persistent storage for this PRD)                                       
- Key model changes: EnforceIssuanceProfile bool, ServerKeyGenEnabled bool, CKGTrustedEncryptionCAs []string added to                 
EnrollmentOptionsLWCRFC9483                                                                                                           
- CKG key transport: Key Transport (RSA-OAEP) and Key Agreement (ECDH); algorithm selected by controller based on EE encryption cert  
key type                                                                                                                              
                                                                                                                                    
---                                                                                                                                   
Proposed vertical slices                                                                                                            
                        
Phase 1 — Authentication & Protocol Integrity
Stories: 5, 6, 7, 12, 13, 14, 32, 33, 34, 35, 36, 37, 43, 45, 48                                                                      
Auth middleware (mTLS validation against DMS CAs), EE signature verification on inbound messages, extraCerts populated in all         
responses, implicitConfirm generalInfo handling. This is the foundational correctness layer — existing enrollment/reenroll continue to
  work, but are now properly authenticated and protected.                                                                              
                                                                                                                                      
---                                                                                                                                 
Phase 2 — Revocation (rr/rp)
Stories: 18, 19, 20, 44 (revocation)                                                                                                  
Dispatch for body tag 11, ASN.1 structures for RevReqContent/RevRepContent, implement LWCRevokeCertificate fully, E2E test: enroll → 
revoke via openssl cmp -cmd rr.                                                                                                       
                                                                                                                                      
---
Phase 3 — PKCS#10 Enrollment (p10cr)                                                                                                  
Stories: 3, 4, 46 (p10cr)                                                                                                             
Dispatch for body tag 4, parse embedded PKCS#10 CSR directly (no CertTemplate extraction needed), verify CSR self-signature, call 
LWCEnroll, E2E test: openssl cmp -cmd p10cr.                                                                                          
                                                                                                                                      
---
Phase 4 — CertTemplate Extension Forwarding                                                                                           
Stories: 38, 39                                                                                                                       
Add EnforceIssuanceProfile to model and DMS REST API. When false: extract SANs, key usage, EKU from CertTemplate and forward to CA. 
When true: current behavior (subject + pubkey only). Tests for both modes on ir/cr/kur.                                               
                                                                                                                                      
---
Phase 5 — Support Messages (genm/genp)                                                                                                
Stories: 21, 22, 23, 24, 25                                                                                                         
Dispatch for body tag 21, sub-dispatch on 4 InfoType OIDs, implement all four service stubs (LWCCACerts already works, 
LWCGetRootCACertUpdate, LWCGetCertReqTemplate, LWCGetCRL fully implemented), ASN.1 structures for genm/genp, E2E test for each.
                                                                                                                                      
---
Phase 6 — Central Key Generation (CKG)                                                                                                
Stories: 26, 27, 28, 29, 30, 31, 40, 41                                                                                             
Add ServerKeyGenEnabled / CKGTrustedEncryptionCAs to model. Detect empty public key in CertTemplate (ir/cr), add LWCServerKeyGen 
service method (KMS-generated key, EnvelopedData wrapping), implement Key Transport + Key Agreement, validate EE encryption cert, E2E 
test.                                                                                                                                 
      
---                                                                                                                                   
Questions for you:                                                                                                                    

1. Does the granularity feel right, or should any phases be merged / split?                                                           
2. Should Phase 1 (auth + integrity) be split into two — one for the mTLS middleware alone (which unblocks the rest), and one for   
protection validation + extraCerts?                                                                                                   
3. Phases 2 and 3 are small. Should they be merged into a single "Missing enrollment operations" phase?
4. Any ordering constraints I should know about — e.g. must Phase 4 (extension forwarding) land before a specific release?            
                                                                                                                                      