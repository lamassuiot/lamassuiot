package oracle

import (
	"context"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
)

type kmsContractRepository struct {
	name string
	repo storage.KMSKeysRepo
}

func testKMSRepositoryContracts(t *testing.T, ctx context.Context, repos ...kmsContractRepository) {
	t.Helper()
	baseTime := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	first := &models.Key{
		KeyID: "storage-contract-key", EngineID: "storage-contract-a", Name: "Alpha Key",
		Algorithm: "RSA", Size: 4096, PublicKey: "contract-public-key-a", CreationTS: baseTime,
		Aliases: []string{"contract-alias-a"}, Tags: []string{"blue", "Prod"},
		Metadata: map[string]any{"score": 21, "enabled": true, "note": "alpha"},
	}
	second := &models.Key{
		KeyID: "storage-contract-key", EngineID: "storage-contract-b", Name: "beta key",
		Algorithm: "RSA", Size: 1024, PublicKey: "contract-public-key-b", CreationTS: baseTime.Add(time.Minute),
		Aliases: []string{"contract-alias-b"}, Tags: []string{"red"},
		Metadata: map[string]any{"score": 9, "enabled": false, "note": "beta"},
	}

	filters := []struct {
		name  string
		field string
		op    resources.FilterOperation
		value string
		want  int
	}{
		{"string equal", "name", resources.StringEqual, "Alpha Key", 1},
		{"string not equal", "name", resources.StringNotEqual, "Alpha Key", 1},
		{"string equal ignore case", "name", resources.StringEqualIgnoreCase, "ALPHA KEY", 1},
		{"string not equal ignore case", "name", resources.StringNotEqualIgnoreCase, "ALPHA KEY", 1},
		{"string contains", "name", resources.StringContains, "pha", 1},
		{"string contains ignore case", "name", resources.StringContainsIgnoreCase, "KEY", 2},
		{"string not contains", "name", resources.StringNotContains, "pha", 1},
		{"string not contains ignore case", "name", resources.StringNotContainsIgnoreCase, "PHA", 1},
		{"string in", "name", resources.StringIn, "Alpha Key,beta key", 2},
		{"string not in", "name", resources.StringNotIn, "Alpha Key", 1},
		{"enum equal", "algorithm", resources.EnumEqual, "RSA", 2},
		{"enum not equal", "algorithm", resources.EnumNotEqual, "RSA", 0},
		{"enum in", "algorithm", resources.EnumIn, "RSA,EC", 2},
		{"number equal", "size", resources.NumberEqual, "4096", 1},
		{"number not equal", "size", resources.NumberNotEqual, "4096", 1},
		{"number less than", "size", resources.NumberLessThan, "4096", 1},
		{"number less or equal", "size", resources.NumberLessOrEqualThan, "4096", 2},
		{"number greater than", "size", resources.NumberGreaterThan, "1024", 1},
		{"number greater or equal", "size", resources.NumberGreaterOrEqualThan, "1024", 2},
		{"date equal", "creation_ts", resources.DateEqual, baseTime.Format(time.RFC3339Nano), 1},
		{"date before", "creation_ts", resources.DateBefore, baseTime.Add(30 * time.Second).Format(time.RFC3339Nano), 1},
		{"date after", "creation_ts", resources.DateAfter, baseTime.Add(30 * time.Second).Format(time.RFC3339Nano), 1},
		{"array contains", "tags", resources.StringArrayContains, "blue", 1},
		{"array contains ignore case", "tags", resources.StringArrayContainsIgnoreCase, "prod", 1},
		{"JSONPath numeric predicate", "metadata", resources.JsonPathExpression, `$.score >= 20`, 1},
		{"JSONPath Boolean predicate", "metadata", resources.JsonPathExpression, `$.enabled == true`, 1},
	}

	for _, contract := range repos {
		t.Run(contract.name, func(t *testing.T) {
			for _, key := range []*models.Key{first, second} {
				if _, err := contract.repo.Insert(ctx, key); err != nil {
					t.Fatalf("insert %s/%s: %v", key.KeyID, key.EngineID, err)
				}
				keyID, engineID := key.KeyID, key.EngineID
				t.Cleanup(func() {
					if err := contract.repo.Delete(ctx, keyID, engineID); err != nil {
						t.Errorf("cleanup key %s/%s: %v", keyID, engineID, err)
					}
				})
			}

			if rows, err := contract.repo.SelectByKeyID(ctx, first.KeyID); err != nil || len(rows) != 2 {
				t.Fatalf("composite key lookup rows=%d error=%v", len(rows), err)
			}
			if found, key, err := contract.repo.SelectExistsByAlias(ctx, "contract-alias-a"); err != nil || !found || key.EngineID != first.EngineID {
				t.Fatalf("alias lookup found=%v key=%+v error=%v", found, key, err)
			}
			for _, tc := range filters {
				got, err := contract.repo.CountWithFilters(ctx, &resources.QueryParameters{
					Filters: []resources.FilterOption{
						{Field: "key_id", FilterOperation: resources.StringEqual, Value: first.KeyID},
						{Field: tc.field, FilterOperation: tc.op, Value: tc.value},
					},
				})
				if err != nil || got != tc.want {
					t.Errorf("%s: count=%d want=%d error=%v", tc.name, got, tc.want, err)
				}
			}

			updated := *first
			updated.Name = "renamed alpha"
			updated.Metadata = map[string]any{"score": 22, "enabled": true}
			if _, err := contract.repo.Update(ctx, &updated); err != nil {
				t.Fatalf("update: %v", err)
			}
			if found, key, err := contract.repo.SelectExistsByKeyID(ctx, first.KeyID, first.EngineID); err != nil || !found || key.Name != updated.Name || key.Metadata["score"] != float64(22) {
				t.Fatalf("updated key found=%v key=%+v error=%v", found, key, err)
			}
		})
	}
}
