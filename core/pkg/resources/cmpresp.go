package resources

import "time"

// CMPTransactionResponse is the HTTP wire format for a single CMP transaction
// row. The raw CertDER and CSRDER blobs are intentionally NOT returned: they
// can be megabytes-large per row and the management UI only needs cert
// metadata. CertSerialNumber is the hex serial of the issued cert (lowercase)
// when CertDER is populated; empty otherwise.
//
// State is the string form of storage.CMPTransactionState ("PENDING",
// "ISSUED", "ISSUE_FAILED", "CONFIRMED", "REVOKED"); we keep it as a plain
// string here to avoid an engines/storage import cycle from the resources package.
type CMPTransactionResponse struct {
	TransactionID     string     `json:"transaction_id"`
	DMSID             string     `json:"dms_id"`
	State             string     `json:"state"`
	IsReenrollment    bool       `json:"is_reenrollment"`
	RequestType       string     `json:"request_type,omitempty"`
	SubjectCommonName string     `json:"subject_common_name,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	ExpiresAt         time.Time  `json:"expires_at"`
	ConfirmedAt       *time.Time `json:"confirmed_at,omitempty"`
	ErrorMessage      string     `json:"error_message,omitempty"`
	CertSerialNumber  string     `json:"certificate_serial_number,omitempty"`
	HasCertificate    bool       `json:"has_certificate"`
}

type GetCMPTransactionsResponse struct {
	IterableList[CMPTransactionResponse]
}
