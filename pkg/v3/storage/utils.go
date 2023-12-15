package storage

import (
	"github.com/lamassuiot/lamassuiot/pkg/v3/resources"
)

type StorageListRequest[E any] struct {
	ExhaustiveRun bool
	ApplyFunc     func(E)
	QueryParams   *resources.QueryParameters
	ExtraOpts     map[string]interface{}
}
