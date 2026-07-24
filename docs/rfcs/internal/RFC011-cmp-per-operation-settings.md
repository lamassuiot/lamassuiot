# RFC011: CMP Per-Operation Settings — Schema and Enforcement

## Problem Statement

RFC010 brought the DMS Manager's CMP support to protocol parity with EST, but every
operation (ir, cr, p10cr, kur, rr, genm, ccr) shared one flat set of DMS-level knobs
(`EnrollmentOptionsLWCRFC9483`): a single `auth_mode`, a single `EnforcePOPO`, a single
`Workflow`, and so on. In practice, operators need policy that differs per operation —
e.g. a DMS that accepts unauthenticated `ir` (bootstrap) but requires signature-protected,
CA-chain-validated `rr` (revocation), or that caps how many concurrently active
certificates a device may hold via `cr` without capping `ir`. There was no way to express
that.

A first phase (dashboard-only) introduced a nested, per-operation configuration schema —
`CMPIRSettings`, `CMPCRSettings`, `CMPP10CRSettings`, `CMPKURSettings`, `CMPRRSettings`,
`CMPGENMSettings`, `CMPCCRSettings` (`core/pkg/models/dms_cmp_operations.go`) — that
persists and round-trips through the DMS API and the dashboard's settings editor
(`CmpPlannedOperationTabs.tsx`), with `ResolveCMPSettings`
(`core/pkg/models/dms_cmp_settings.go`) defaulting every field on every `GetDMSByID` call.
At that point only two fields were actually consulted by request handlers (see "CKG
bridge" and "KUR bridge" below); everything else persisted without effect.

This RFC documents the schema's enforcement semantics as of the second phase, which wires
the remaining fields into the CMP controllers (`backend/pkg/controllers/cmp/`) and the
DMS Manager service (`backend/pkg/services/dmsmanager_lwcmp.go`).

## Design

### General vs. per-operation

The flat fields on `EnrollmentOptionsLWCRFC9483` remain the DMS-general level:
`AuthMode`, `AuthOptionsMTLS`/`AuthOptionsExternalWebhook`, `ProtectionCertificateSerialNumber`,
`AcceptImplicit`, `ConfirmationTimeout`, `Workflow`, `ApprovalTimeout`. Every operation's
`PolicyOverrides` struct (`Workflow`, `Confirmation`, `IssuanceProfileID`, each
`inherit`-able) lets a single operation deviate from those general values without
duplicating them; `inherit` (the default) means "use the general-level value unchanged."

### Two pre-existing bridges (unchanged by this phase)

- **CKG bridge**: `ServerKeyGenEnabled` (general) and `IR.CentralKeyGeneration.Enabled` /
  `CR.CentralKeyGeneration.Enabled` are unified by OR into one effective value, written
  back to all three by `ResolveCMPSettings`, so the one shared KGA gate in
  `cmp_enrollment.go` stays authoritative regardless of which field an operator sets
  (RFC011 Open Q1, resolved as "option a": one shared toggle rather than fully independent
  per-op KGA policy).
- **KUR bridge**: `CMPKURSettings.RenewalWindow` / `AllowExpiredCertificate` /
  `AdditionalValidationCAIDs` / `RevokeSupersededCertificate` are reshaped 1:1 onto the
  shared `ReEnrollmentSettings` (nested value wins when set), so the pre-existing
  `LWCReenroll` enforcement (window, expiry, validation CAs, revoke-on-reenroll) honours
  them without new code. Because `ReEnrollmentSettings` is also consumed by EST
  re-enrollment and certificate-expiry monitoring, configuring these fields via the CMP
  `kur` block affects those paths too — decoupling per-protocol re-enrollment policy is
  deliberately out of scope.

### Operation identity: how one enrollment path knows ir from cr from p10cr

`ir`, `cr`, and `p10cr` are dispatched through one shared pipeline
(`handleEnrollment` → `issueAndStore`/`deferForApproval` → `DMSManagerServiceBackend.LWCEnroll`).
Everywhere the pipeline still has the parsed request (`body.Tag`, `issueParams.requestTag`),
operation-specific settings are selected directly by tag. Past that point — inside
`LWCEnroll`, which needs to apply `CR`-only fields — the operation identity is carried on
`ctx` via `core.LamassuContextKeyCMPOperation` (values `"ir"`/`"cr"`/`"p10cr"`, set in
`issueAndStore` and again across the phased-workflow admin-approval boundary in
`ApproveCMPTransaction`; absent/unrecognized defaults to `"ir"`, the least-restrictive
choice since `ir` has no allow-list-style fields). `cmpOperationFromContext` reads it back.

This context-value pattern mirrors the pre-existing
`core.LamassuContextKeyPreAuthenticated` / `LamassuContextKeyCMPDeferredCommit` signals used
for the same kind of side-channel between the controller and the shared service method,
rather than widening the `services.LightweightCMPService` interface (which would ripple
into every mock, audit/eventpub middleware, and the SDK client for a value only `LWCEnroll`
needs).

## Enforcement Summary

### IR (Initialization Request)

| Field | Enforcement |
|---|---|
| `enabled` | Gated at the `HandleCMP` dispatch switch (`operationEnabled`). |
| `registration_mode` / `existing_device_policy` | `registration_mode` overrides the DMS-general `RegistrationMode` for this call when set to `jitp`/`pre_registration` (`inherit` defers to the general value). `existing_device_policy` is asymmetric: `replace` forces `EnableReplaceableEnrollment` on for this call, but `reject` does **not** force it off — `CMPExistingDevicePolicy` has no `inherit` sentinel and always concretizes to `reject` when unset, so treating `reject` as an override would silently defeat a DMS that explicitly turned general replaceable enrollment on and never touched this per-op field (`applyCMPOpRegistrationOverride`). |
| `identity_source` | Persisted only (not yet enforced — `subject_only` would need to reject the SAN-fallback path in `deviceIdentityFromCSR`). |
| `proof_of_possession.allowed_methods` | Allow-list gate per method (signature / trusted_ra / challenge_response / encrypted_certificate) in `handleEnrollment`. |
| `proof_of_possession.required` | Overrides the legacy `EnforcePOPO` flag for this call (`popoPolicy.Required` passed to `verifyPOPO`). |
| `registration_token.mode` | `disabled`/`required`/`optional` gates on the regToken control's mere presence (`req.RegToken != ""`), independent of the one-time-use check that follows. IR-only — `CMPCRSettings` has no such field. |
| `authenticator_control.mode` | Same disabled/required/optional gating, on presence detected via `corecmp.HasAuthenticatorControl`. IR-only. |
| `central_key_generation.allowed_recipient_methods` | Allow-list gate (KTRI↔rsa_key_transport / KARI↔ecdh_key_agreement) in `handleKGAEnrollment` via `ckgRecipientMethodAllowed`. |
| `policy_overrides.issuance_profile_id` | Pins a specific issuance profile ahead of the DMS-general one (`resolveCMPIssuanceProfile`). |

### CR (Certification Request — device already in the PKI)

| Field | Enforcement |
|---|---|
| `enabled` | Dispatch gate, as IR. |
| `require_existing_device` | Rejects the request outright when no device is registered under the derived device ID. |
| `maximum_active_certificates` | Caps how many non-revoked certificates (across the device's identity-slot version history) the device may hold; 0 = no cap. Counted live against the CA via `countActiveDeviceCertificates` — there is no dedicated "certs per device" index. |
| `certificate_behavior` | `replace` forces revocation of the device's previously active certificate once the new one issues; `additional` keeps it valid. Overrides the general `ReEnrollmentSettings.RevokeOnReEnrollment` gate for `cr` specifically. **Limitation:** the device model tracks one active identity slot per device (a single `ActiveVersion` pointer), so `additional` cannot mint a second *concurrently active* identity — it can only choose not to revoke the previous certificate. True parallel multi-slot identities are out of scope for this phase. |
| `allowed_profile_ids` / `policy_overrides.issuance_profile_id` | Same profile-pinning as IR, plus an allow-list: the resolved profile (pinned or DMS-default) is rejected if non-empty `allowed_profile_ids` doesn't contain it. |
| `proof_of_possession.*`, `central_key_generation.*` | Same enforcement as IR, selected by `body.Tag == CR` instead. |

### P10CR (PKCS#10 Certification Request)

| Field | Enforcement |
|---|---|
| `enabled` | Dispatch gate. |
| `registration_mode` / `existing_device_policy` | Same override mechanism as IR. |
| `allowed_profile_ids` / `policy_overrides.issuance_profile_id` | Same as CR. |

Fixed, non-configurable invariants (RFC 9483 §4.1.4): the PKCS#10 signature is always
verified as the POPO; there is no CRMF POPO to configure; central key generation is
unavailable (the client supplies its own key); CRMF registration controls
(regToken/authenticator) do not apply.

### KUR (Key Update Request)

| Field | Enforcement |
|---|---|
| `enabled` | Dispatch gate. |
| `renewal_window`, `allow_expired_certificate`, `additional_validation_ca_ids`, `revoke_superseded_certificate` | Live via the KUR bridge into `ReEnrollmentSettings` (pre-existing enforcement, unchanged by this phase). |
| `key_policy` | `require_new_key` rejects a request whose CSR public key matches the certificate being updated (`bytes.Equal` on `RawSubjectPublicKeyInfo`). |
| `identity_change_policy` | `forbid` requires exact subject+SAN match; `san_only` requires exact subject match (SAN may differ); `subject_and_san` permits any change. Compared via `sanSignature`/`sanSignatureCert`, an order-independent canonical SAN string. |

Fixed, non-configurable invariants (RFC 9483 §4.1.3): the certificate being updated must
protect the request; a second key-update for the same certificate is rejected while the
first is unconfirmed; the old identity remains active until confirmation; an unconfirmed
new certificate is revoked on timeout.

### RR (Revocation Request)

| Field | Enforcement |
|---|---|
| `enabled` | Dispatch gate. |
| *(fixed invariant, not a field)* | An `rr` is **always** signature-protected, regardless of the DMS's `auth_mode` — `requireProtection` is forced `true` when `body.Tag == RR`. An unsigned revocation is never accepted, even under `NO_AUTH`/`EXTERNAL_WEBHOOK`. |
| `authorization` | `self_only` rejects a third party revoking someone else's certificate; `self_and_trusted_ra` additionally accepts a signer validated via `trusted_ra`. |
| `trusted_ra.require_cmc_ra_eku` / `trusted_ra.validation_ca_ids` | Configurable EKU requirement and CA scope for the trusted-RA path (`validateTrustedRASigner`); empty `validation_ca_ids` falls back to the DMS's general trust boundary (`trustedRACAIDs`). |
| `allow_revival` | Gates whether a revoked certificate may be un-revoked (`removeFromCRL`/hold-release). |
| `allow_expired_target` | Gates whether an already-expired certificate may still be revoked. |
| `allowed_reasons` | Restricts which RFC 5280 `CRLReason` codes the DMS accepts, mapped via `cmpRevocationReasonName`/`cmpReasonAllowed`. |

### GENM (General Messages)

| Field | Enforcement |
|---|---|
| `access_policy` | `require_signed` rejects an unsigned genm (`signerCert == nil`); `public_discovery` answers unauthenticated requests. |
| `information_types.*` | Per-`id-it-*` OID gate (`genmInfoTypeEnabled`) — a genm requesting an information type the DMS has turned off is rejected rather than silently answered. |

### CCR (Cross-Certification — CA-to-CA, privileged)

| Field | Enforcement |
|---|---|
| `enabled` | Dispatch gate; **defaults off** (RFC011 treats cross-certification as a privileged CA operation, per explicit product direction). |
| `require_ca_certificate` | The signer certificate must carry `IsCA` (configurable; RFC 4210bis §5.3.11 default is that only CAs may send ccr). |
| `require_proof_of_possession` | Requires a `POPOSigningKey`; an absent/raVerified POPO is rejected. EncryptedKey POPOs (which would disclose the requester's private key) are rejected unconditionally regardless of this setting. |
| `trusted_requester_ca_ids` | An allow-list of CA IDs the signer must chain to, beyond the `IsCA` check — closes a gap where any self-issued CA certificate satisfying `require_ca_certificate` could request cross-certification. Empty = unrestricted. Enforced via the new `LWCValidateCCRRequester` service method (`services.LightweightCMPCrossCertRequesterValidator`), mirroring the existing `LWCValidateRASigner` pattern. |
| `maximum_validity` | Caps the cross-certificate's requested lifetime (replaces the historical fixed `crossCertValidity` constant when set). |
| `subject_constraints` | DN-substring and dNSName-suffix allow-lists (`validateCCRSubjectConstraints`); empty on a dimension means unconstrained on that dimension. |
| `workflow` | `administrator_approval` defers issuance: the request is persisted as a `PENDING` `CMPTransaction` (`RequestType="ccr"`) and answered with a CMP "waiting" `ccp`, mirroring `ir`/`cr`'s phased workflow (`deferForApproval`). An administrator calls `ApproveCMPTransaction`, which now branches on `RequestType == "ccr"` to call `LWCIssueCrossCertificate` instead of `LWCEnroll`/`LWCReenroll`; the requesting CA retrieves the cross-certificate via `pollReq` (response tag `ccp`, wired into `pollRespTagFor`). **Limitation:** the requested validity window (`tmpl.notBefore`/`notAfter`) is not persisted on the transaction row — admin-approved issuance falls back to `CCR.MaximumValidity`/profile default rather than the pre-approval request's requested window, since the schema has no field for it and administrator review is expected to re-derive validity from policy rather than trust the request verbatim. |

## Fields intentionally NOT enforced (and why)

- **`identity_source` (IR)**: no code path currently distinguishes "must use CN" from
  "may fall back to SAN" strongly enough to justify the change; left for a future
  iteration if a concrete DMS needs it.
- **regToken values in DMS config**: explicitly kept OUT of the nested schema (RFC011 Open
  Q2). regToken/authenticator-control *values* are one-time-use or pre-shared credentials
  that must be provisioned or generated independently, not stored as DMS configuration —
  only their `mode` (disabled/optional/required) lives in the schema.

## Testing

- Controller-level tests mock the service and set `EnrollmentOptionsLWCRFC9483` directly;
  because the mock does not run `ResolveCMPSettings`, tests exercising per-operation
  enforcement must set the relevant nested block explicitly (or call
  `models.ResolveCMPSettings`) — a bare zero-value struct leaves every `enabled` field
  `false` and trips the dispatch gate before reaching the behavior under test.
  Real-service E2E tests (`backend/pkg/assemblers/tests/dms-manager/cmp/`) exercise the
  full `ResolveCMPSettings` defaulting path.
- Enabling the per-operation `enabled` gates is a **behavior-breaking change** versus the
  historical always-on behavior: `p10cr` and `ccr` now default OFF and must be explicitly
  enabled. The RR always-signature-protected invariant also contradicts
  `TestHandleCMP_RR_DefaultReason`, which posted an unprotected `rr` under non-client-cert
  auth and asserted success; that test was updated to sign the request.
