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
)
