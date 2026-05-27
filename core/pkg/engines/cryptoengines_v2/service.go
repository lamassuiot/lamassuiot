package cryptoenginesv2

import (
	"context"
	"time"
)

type Operation string

type Service interface {
	// --- Lifecycle ---
	CreateKey(ctx context.Context, spec CreateKeySpec) (KeyHandle, error)
	ImportKey(ctx context.Context, spec ImportKeySpec) (KeyHandle, error)
	GetKey(ctx context.Context, id KeyID) (KeyHandle, error)
	ListKeys(ctx context.Context, opts ListOpts) (ListKeysResult, error)
	UpdateKey(ctx context.Context, id KeyID, patch KeyPatch) (KeyMetadata, error)

	// --- State ---
	EnableKey(ctx context.Context, id KeyID) error
	DisableKey(ctx context.Context, id KeyID) error
	ScheduleDeletion(ctx context.Context, id KeyID, after time.Duration) error
	CancelDeletion(ctx context.Context, id KeyID) error

	// --- Backup ---
	BackupKey(ctx context.Context, id KeyID) (BackupBlob, error)
	RestoreKey(ctx context.Context, blob BackupBlob) (KeyHandle, error)

	// --- Aliases ---
	CreateAlias(ctx context.Context, alias string, target KeyID) error
	DeleteAlias(ctx context.Context, alias string) error
	ResolveAlias(ctx context.Context, alias string) (KeyID, error)

	// --- RNG ---
	GenerateRandom(ctx context.Context, n int) ([]byte, error)
}
