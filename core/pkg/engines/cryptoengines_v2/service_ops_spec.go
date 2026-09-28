package cryptoenginesv2

import "crypto"

type EncryptOpts struct {
	Hash           crypto.Hash
	AssociatedData []byte
}

type WrapOpts struct {
	Hash           crypto.Hash
	InnerAlgorithm AlgorithmID
	AssociatedData []byte
}

type SymmetricOpts struct {
	Nonce          []byte
	AssociatedData []byte
}

type Ciphertext struct {
	Algorithm AlgorithmID
	Nonce     []byte
	Bytes     []byte
	AAD       []byte
}

type KDFParams struct {
	Algorithm AlgorithmID
	Salt      []byte
	Info      []byte
	Length    int
}
