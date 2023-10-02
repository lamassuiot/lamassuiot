package models

type SignMessageType string

const (
	Raw    SignMessageType = "raw"
	Hashed SignMessageType = "hash"
)
