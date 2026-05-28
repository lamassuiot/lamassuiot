package core

const (
	LamassuContextKeyAuthID      string = "lamassu.io/ctx/auth-id"
	LamassuContextKeyAuthContext string = "lamassu.io/ctx/auth-context"
	LamassuContextKeyAuthType    string = "lamassu.io/ctx/auth-type"
	LamassuContextKeyRequestID   string = "lamassu.io/ctx/request-id"
	LamassuContextKeySource      string = "lamassu.io/ctx/source"
	LamassuContextKeyHTTPRequest string = "lamassu.io/ctx/http-request"

	LamassuContextKeyEventType    string = "lamassu.io/ctx/cloudevent/type"
	LamassuContextKeyEventSubject string = "lamassu.io/ctx/cloudevent/subject"

	// LamassuContextKeyPreAuthenticated signals that the request's enrollment
	// authentication was already performed at submission time (e.g. phased
	// workflow: the original IR was authenticated; the admin-approval step
	// should not re-run client-cert validation since no CMP signer is present).
	LamassuContextKeyPreAuthenticated string = "lamassu.io/ctx/pre-authenticated"
)
