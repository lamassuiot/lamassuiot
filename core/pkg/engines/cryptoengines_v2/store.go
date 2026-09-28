package cryptoenginesv2

import "context"

// MetadataStore: everything persistent EXCEPT private material.
type MetadataStore interface {
	Put(ctx context.Context, rec KeyRecord) error
	Get(ctx context.Context, id KeyID) (KeyRecord, error)
	List(ctx context.Context, opts ListOpts) (ListKeysResult, error)
	Delete(ctx context.Context, id KeyID) error
	UpdateState(ctx context.Context, id KeyID, from, to KeyState) error

	PutAlias(ctx context.Context, alias string, target KeyID) error
	GetAlias(ctx context.Context, alias string) (KeyID, error)
	DeleteAlias(ctx context.Context, alias string) error
}

type KeyRecord struct {
	Metadata   KeyMetadata
	BackendRef BackendRef
}
