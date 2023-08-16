package postgres

import (
	"context"
	"testing"

	"gorm.io/driver/sqlite" // Sqlite driver based on CGO
	"gorm.io/gorm"
)

func TestCount(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
	}{
		{
			name: "OK/0",
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dbCli, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
			if err != nil {
				t.Errorf("could not create db client: %s", err)
			}

			caStore, err := NewCAPostgresRepository(dbCli)
			if err != nil {
				t.Errorf("could not create CA store: %s", err)
			}

			count, err := caStore.Count(context.Background())
			if err != nil {
				t.Errorf("could not count CAs: %s", err)
			}

			if count != 0 {
				t.Errorf("got count %d, want %d", count, 0)
			}
		})
	}
}
