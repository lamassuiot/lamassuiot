package sdk

// authzQueryContextKey is an unexported type to prevent collisions with other
// packages using context.WithValue on the same string literal.
type authzQueryContextKey struct{}

// AuthzQueryKey is the context key used to store and retrieve the authorization
// filter query. Use it with context.WithValue and ctx.Value.
var AuthzQueryKey = authzQueryContextKey{}
