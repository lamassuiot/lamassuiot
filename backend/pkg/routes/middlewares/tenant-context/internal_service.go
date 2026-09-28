package tenantcontext

import (
	"context"
	"net/http"
)

// InternalServiceActorType identifies another Lamassu service calling through
// the internal mTLS listener.
const InternalServiceActorType = "INTERNAL_SERVICE"

type internalServiceContextKey struct{}

// MarkInternalServiceRequest wraps the handler of the internal listener. The
// TLS layer has already verified the client certificate against the internal
// CA; the mark is set server-side, so a request arriving on any other listener
// cannot claim to be an internal service (headers are never trusted).
func MarkInternalServiceRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "internal service certificate required", http.StatusUnauthorized)
			return
		}
		certificate := r.TLS.PeerCertificates[0]
		identity := AuthenticatedIdentity{
			Issuer:    certificate.Issuer.String(),
			Subject:   certificate.Subject.CommonName,
			ActorType: InternalServiceActorType,
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), internalServiceContextKey{}, identity)))
	})
}

// internalServiceIdentity returns the internal service identity set by
// MarkInternalServiceRequest, if the request came through the internal listener.
func internalServiceIdentity(ctx context.Context) (AuthenticatedIdentity, bool) {
	identity, ok := ctx.Value(internalServiceContextKey{}).(AuthenticatedIdentity)
	return identity, ok && identity.Subject != ""
}
