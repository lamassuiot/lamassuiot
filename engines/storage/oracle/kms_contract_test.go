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

// testEmptyStringFilterContract checks that string filters see an empty value
// the same way on every repository. Oracle stores it as NULL; PostgreSQL as an
// empty string, which "not equal", "not contains" and "not in" filters keep.
func testEmptyStringFilterContract(t *testing.T, ctx context.Context, repos ...kmsContractRepository) {
	t.Helper()
	const keyID = "empty-string-contract"
	keys := []*models.Key{
		{KeyID: keyID, EngineID: "empty-name", Name: "", Algorithm: "RSA", Size: 2048, PublicKey: "pk-empty",
			CreationTS: time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC), Aliases: []string{}, Tags: []string{}},
		{KeyID: keyID, EngineID: "x-name", Name: "x", Algorithm: "RSA", Size: 2048, PublicKey: "pk-x",
			CreationTS: time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC), Aliases: []string{}, Tags: []string{}},
	}
	filters := []struct {
		name  string
		field string
		op    resources.FilterOperation
		value string
		want  int
	}{
		{"equal empty", "name", resources.StringEqual, "", 1},
		{"equal value", "name", resources.StringEqual, "x", 1},
		{"not equal value keeps empty", "name", resources.StringNotEqual, "x", 1},
		{"not equal empty", "name", resources.StringNotEqual, "", 1},
		{"equal ignore case empty", "name", resources.StringEqualIgnoreCase, "", 1},
		{"not equal ignore case keeps empty", "name", resources.StringNotEqualIgnoreCase, "X", 1},
		{"contains empty matches all", "name", resources.StringContains, "", 2},
		{"contains ignore case empty matches all", "name", resources.StringContainsIgnoreCase, "", 2},
		{"contains value", "name", resources.StringContains, "x", 1},
		{"not contains keeps empty", "name", resources.StringNotContains, "x", 1},
		{"not contains ignore case keeps empty", "name", resources.StringNotContainsIgnoreCase, "X", 1},
		{"not contains empty matches none", "name", resources.StringNotContains, "", 0},
		{"in ignores empty items", "name", resources.StringIn, "x,", 1},
		{"in of empty items applies no filter", "name", resources.StringIn, ",", 2},
		{"not in keeps empty", "name", resources.StringNotIn, "x", 1},
		{"not in ignores empty items", "name", resources.StringNotIn, "x,", 1},
		{"not in ignore case keeps empty", "name", resources.StringNotInIgnoreCase, "X", 1},
		{"CLOB not equal", "public_key", resources.StringNotEqual, "pk-x", 1},
		{"CLOB equal", "public_key", resources.StringEqual, "pk-x", 1},
		{"CLOB equal escapes wildcards", "public_key", resources.StringEqual, "pk_x", 0},
		{"CLOB equal ignore case", "public_key", resources.StringEqualIgnoreCase, "PK-X", 1},
		{"CLOB in", "public_key", resources.StringIn, "pk-x,pk-other,", 1},
		{"CLOB not in", "public_key", resources.StringNotIn, "pk-x", 1},
	}
	for _, contract := range repos {
		t.Run(contract.name+" empty strings", func(t *testing.T) {
			for _, key := range keys {
				persisted := *key
				if _, err := contract.repo.Insert(ctx, &persisted); err != nil {
					t.Fatalf("insert %s/%s: %v", key.KeyID, key.EngineID, err)
				}
				engineID := key.EngineID
				t.Cleanup(func() {
					if err := contract.repo.Delete(ctx, keyID, engineID); err != nil {
						t.Errorf("cleanup key %s/%s: %v", keyID, engineID, err)
					}
				})
			}
			for _, tc := range filters {
				got, err := contract.repo.CountWithFilters(ctx, &resources.QueryParameters{
					Filters: []resources.FilterOption{
						{Field: "key_id", FilterOperation: resources.StringEqual, Value: keyID},
						{Field: tc.field, FilterOperation: tc.op, Value: tc.value},
					},
				})
				if err != nil || got != tc.want {
					t.Errorf("%s: count=%d want=%d error=%v", tc.name, got, tc.want, err)
				}
			}
		})
	}
}
