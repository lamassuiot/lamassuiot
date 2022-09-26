package service

import (
	"context"

	"github.com/go-playground/validator/v10"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/api/errors"
)

type validationMiddleware struct {
	next Service
}

func NewInputValudationMiddleware() Middleware {
	return func(next Service) Service {
		return &validationMiddleware{
			next: next,
		}
	}
}

func (mw *validationMiddleware) Health(ctx context.Context) (healthy bool) {
	return mw.next.Health(ctx)
}

func (mw *validationMiddleware) Verify(ctx context.Context, msg []byte) ([]byte, error) {
	validate := validator.New()
	err = validate.Struct(input)
	if err != nil {
		valError := errors.ValidationError{
			Msg: err.Error(),
		}
		return nil, &valError
	}
	return mw.next.Verify(ctx, input)
}
