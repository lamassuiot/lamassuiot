package localfs

import (
	"context"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	fsstorage "github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/fs-storage"
	"github.com/sirupsen/logrus"
)

func TestRegisterLocalFilesystem(t *testing.T) {
	Register()

	builder := fsstorage.GetEngineBuilder(config.LocalFilesystem)
	if builder == nil {
		t.Fatal("local filesystem engine was not registered")
	}

	bucket, err := builder(logrus.NewEntry(logrus.New()), config.FSStorageConfig{
		Type: config.LocalFilesystem,
		Config: map[string]any{
			"storage_directory": t.TempDir(),
		},
	})
	if err != nil {
		t.Fatalf("build local filesystem bucket: %v", err)
	}
	defer bucket.Close()

	ctx := context.Background()
	writer, err := bucket.NewWriter(ctx, "test-key", nil)
	if err != nil {
		t.Fatalf("create test object writer: %v", err)
	}
	if _, err := writer.Write([]byte("test-value")); err != nil {
		t.Fatalf("write test object: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close test object writer: %v", err)
	}

	data, err := bucket.ReadAll(ctx, "test-key")
	if err != nil {
		t.Fatalf("read test object: %v", err)
	}
	if string(data) != "test-value" {
		t.Fatalf("read object = %q, want %q", data, "test-value")
	}
}
