package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	// Sqlite driver based on CGO
)

func TestInsertCAs(t *testing.T) {
	t.Parallel()

	basicCA1 := models.CACertificate{
		ID:                    "123456-789-122-00173",
		Metadata:              map[string]interface{}{},
		Certificate:           models.Certificate{},
		IssuanceExpirationRef: models.Expiration{},
		Type:                  models.CertificateTypeManaged,
		CreationTS:            time.Now(),
	}

	basicCA2 := models.CACertificate{
		ID:                    "756453-734-003-53212",
		Metadata:              map[string]interface{}{},
		Certificate:           models.Certificate{},
		IssuanceExpirationRef: models.Expiration{},
		Type:                  models.CertificateTypeManaged,
		CreationTS:            time.Now(),
	}

	var testcases = []struct {
		name      string
		preInsert []models.CACertificate
		insert    models.CACertificate
		err       error
	}{
		{
			name:      "OK/EmptyDB",
			preInsert: []models.CACertificate{},
			insert:    basicCA1,
			err:       nil,
		},
		{
			name: "OK/NoCollisionCAIDPrimKey",
			preInsert: []models.CACertificate{
				basicCA1,
			},
			insert: basicCA2,
			err:    nil,
		},
		{
			name: "ERR/CollisionCAIDPrimKey",
			preInsert: []models.CACertificate{
				basicCA1,
			},
			insert: basicCA1,
			err:    nil,
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dbCli, err := CreateTestPostgresConnection()
			if err != nil {
				t.Errorf("could not create db client: %s", err)
			}

			querier, err := NewCAPostgresRepository(dbCli)
			if err != nil {
				t.Errorf("could not create CA store: %s", err)
			}

			for _, insertElem := range tc.preInsert {
				_, err := querier.Insert(context.Background(), &insertElem)
				if err != nil {
					t.Errorf("could not perform pre-test operation: %s", err)
				}
			}

			_, err = querier.Insert(context.Background(), &tc.insert)
			if tc.err == nil {
				if err != nil {
					t.Errorf("error not expected could not insert CA: %s", err)
				}
			} else {
				if err == nil {
					t.Errorf("expected '%s' error but got none", tc.err)
				}
			}

		})
	}
}
