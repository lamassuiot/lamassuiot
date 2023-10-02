package storage

import (
	"github.com/lamassuiot/lamassuiot/pkg/v3/resources"
)

type StorageEngine[E any] interface {
	CountAll() (int, error)
	CountByFieldValue(fieldName string, fieldValue string) (int, error)

	SelectByField(fieldValue string, fieldName string) (bool, *E, error)
	SelectAll(exhaustiveRun bool, applyFunc func(*E), queryParams *resources.QueryParameters) (string, error)

	Insert(elem *E) (*E, error)
	Update(elem *E) (*E, error)
	DeleteByID(elemID string) error
}
