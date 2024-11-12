package storage

import (
	"github.com/lamassuiot/lamassuiot/v3/core/pkg/resources"
)

type StorageListRequest[E any] struct {
	ExhaustiveRun bool
	ApplyFunc     func(E)
	QueryParams   *resources.QueryParameters
	ExtraOpts     map[string]interface{}
}
