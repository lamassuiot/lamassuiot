package storage

import (
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
)

type StorageListRequest[E any] struct {
	ExhaustiveRun bool
	ApplyFunc     func(E)
	QueryParams   *resources.QueryParameters
	ExtraOpts     map[string]any
}
