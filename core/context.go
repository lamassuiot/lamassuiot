package core

const (
	LamassuContextKeyAuthID               string = "lamassu.io/ctx/auth-id"
	LamassuContextKeyAuthCredentialString string = "lamassu.io/ctx/auth-credential-string"
	LamassuContextKeyAuthCredentialStruct string = "lamassu.io/ctx/auth-credential-struct"
	LamassuContextKeyAuthContext          string = "lamassu.io/ctx/auth-context"
	LamassuContextKeyAuthType             string = "lamassu.io/ctx/auth-type"
	LamassuContextKeyRequestID            string = "lamassu.io/ctx/request-id"
	LamassuContextKeySource               string = "lamassu.io/ctx/source"
	LamassuContextKeyHTTPRequest          string = "lamassu.io/ctx/http-request"

	LamassuContextKeyEventType    string = "lamassu.io/ctx/cloudevent/type"
	LamassuContextKeyEventSubject string = "lamassu.io/ctx/cloudevent/subject"

	LamassuContextKeyMatchedPrincipals string = "lamassu.io/ctx/matched-principals"

	// LamassuContextKeyPreAuthenticated signals that the request's enrollment
	// authentication was already performed at submission time (e.g. phased
	// workflow: the original IR was authenticated; the admin-approval step
	// should not re-run client-cert validation since no CMP signer is present).
	LamassuContextKeyPreAuthenticated string = "lamassu.io/ctx/pre-authenticated"

	// LamassuContextKeyCMPDeferredCommit signals that the CMP enrollment being
	// processed uses explicit confirmation (RFC 4210 §5.2.8: no implicitConfirm
	// granted), so the device-identity commit — identity-slot bind plus the
	// superseded-certificate side effects — must NOT run at issuance time.
	// The controller performs the commit via LWCCommitEnrollment once the EE's
	// certConf validates (or at implicit-confirm pollReq delivery). Until then
	// the device's previously active certificate remains its authoritative
	// credential, and an abandoned (never-confirmed) update leaves the device
	// untouched.
	LamassuContextKeyCMPDeferredCommit string = "lamassu.io/ctx/cmp-deferred-commit"

	// LamassuContextKeyCMPOperation carries which CMP request body — "ir",
	// "cr", or "p10cr" — is driving the current LWCEnroll call. ir/cr/p10cr
	// share this one service method, but RFC011 defines CR-only settings
	// (certificate_behavior, allowed_profile_ids, require_existing_device,
	// maximum_active_certificates) and per-operation registration_mode /
	// existing_device_policy overrides that must not apply uniformly across
	// all three. Absent or unrecognized is treated as "ir".
	LamassuContextKeyCMPOperation string = "lamassu.io/ctx/cmp-operation"
)
