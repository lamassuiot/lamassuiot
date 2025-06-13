package resources

type CreateKeyBody struct {
	Algorithm string `json:"algorithm"`
	Size      string `json:"size"`
}

type SignMessageBody struct {
	Algorithm string `json:"algorithm"`
	Message   []byte `json:"message"`
}

type VerifySignBody struct {
	Algorithm string `json:"algorithm"`
	Message   []byte `json:"message"`
	Signature []byte `json:"signature"`
}

type ImportKeyBody struct {
	PrivateKey []byte `json:"private_key"`
}
