package services

import "context"

type CRLService interface {
	GetCRL(ctx context.Context, input GetCRLInput) ([]byte, error)
}

type GetCRLInput struct {
	CAID string `validate:"required"`
}
