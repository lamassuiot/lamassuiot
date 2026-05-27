package cryptoenginesv2

const (
	OpSign        Operation = "sign"
	OpVerify      Operation = "verify"
	OpEncrypt     Operation = "encrypt"
	OpDecrypt     Operation = "decrypt"
	OpWrapKey     Operation = "wrapKey"
	OpUnwrapKey   Operation = "unwrapKey"
	OpEncapsulate Operation = "encapsulate"
	OpDecapsulate Operation = "decapsulate"
	OpMAC         Operation = "mac"
	OpVerifyMAC   Operation = "verifyMac"
	OpDeriveKey   Operation = "deriveKey"
	OpAgreeKey    Operation = "agreeKey"
)
