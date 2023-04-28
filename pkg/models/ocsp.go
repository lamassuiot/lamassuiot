package models

type RevocationReasonRFC5280 int

const (
	UnspecifiedRevokeReason          RevocationReasonRFC5280 = 0
	KeyCompromisedRevokeReason       RevocationReasonRFC5280 = 1
	CACompromiseRevokeReason         RevocationReasonRFC5280 = 2
	AffiliationChangedRevokeReason   RevocationReasonRFC5280 = 3
	SupersededRevokeReason           RevocationReasonRFC5280 = 4
	CessationOfOperationRevokeReason RevocationReasonRFC5280 = 5
	CertificateHoldRevokeReason      RevocationReasonRFC5280 = 6
	RemoveFromCRLRevokeReason        RevocationReasonRFC5280 = 8
	PrivilegeWithdrawnRevokeReason   RevocationReasonRFC5280 = 9
	AACompromiseRevokeReason         RevocationReasonRFC5280 = 10
)

type RevocationReason struct {
	RFC5280Code int
	Title       string
	Rationale   string
}

var OCSPRevocationReason = map[RevocationReasonRFC5280]RevocationReason{
	UnspecifiedRevokeReason: {
		Title:     "Unspecified",
		Rationale: "",
	},
	KeyCompromisedRevokeReason: {
		Title:     "Key Compromised",
		Rationale: "The token or disk location where the private key associated with the certificate has been compromised and is in the possession of an unauthorized individual. This can include the case where a laptop is stolen, or a smart card is lost",
	},
	CACompromiseRevokeReason: {
		Title:     "CA Compromise",
		Rationale: "The token or disk location where the CA's private key is stored has been compromised and is in the possession of an unauthorized individual. When a CA's private key is revoked, this results in all certificates issued by the CA that are signed using the private key associated with the revoked certificate being considered revoked",
	},
	AffiliationChangedRevokeReason: {
		Title:     "Affiliation Changed",
		Rationale: "The user has terminated his or her relationship with the organization indicated in the Distinguished Name attribute of the certificate. This revocation code is typically used when an individual is terminated or has resigned from an organization. You do not have to revoke a certificate when a user changes departments, unless your security policy requires different certificate be issued by a departmental CA",
	},
	SupersededRevokeReason: {
		Title:     "Superseded",
		Rationale: "A replacement certificate has been issued to a user, and the reason does not fall under the previous reasons. This revocation reason is typically used when a smart card fails, the password for a token is forgotten by a user, or the user has changed their legal name",
	},
	CessationOfOperationRevokeReason: {
		Title:     "Cessation Of Operation",
		Rationale: "If a CA is decommissioned, no longer to be used, the CA's certificate should be revoked with this reason code. Do not revoke the CA's certificate if the CA no longer issues new certificates, yet still publishes CRLs for the currently issued certificates",
	},
	CertificateHoldRevokeReason: {
		Title:     "Certificate Hold",
		Rationale: "A temporary revocation that indicates that a CA will not vouch for a certificate at a specific point in time. Once a certificate is revoked with a CertificateHold reason code, the certificate can then be revoked with another Reason Code, or unrevoked and returned to use",
	},
	RemoveFromCRLRevokeReason: {
		Title:     "Remove From CRL",
		Rationale: "If a certificate is revoked with the CertificateHold reason code, it is possible to 'unrevoke' a certificate. The unrevoking process still lists the certificate in the CRL, but with the reason code set to RemoveFromCRL",
	},
	PrivilegeWithdrawnRevokeReason: {
		Title:     "Privilege Withdrawn",
		Rationale: "It is known, or suspected, that aspects of the Attribute Authority (AA) validated in the attribute certificate have been compromised.",
	},
}
