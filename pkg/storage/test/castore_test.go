package storage

import (
	"context"
	"crypto/x509"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lamassuiot/lamassuiot/v2/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/pkg/resources"
	"github.com/lamassuiot/lamassuiot/v2/pkg/storage"
	"github.com/lamassuiot/lamassuiot/v2/pkg/storage/postgres"
	postgres_test "github.com/lamassuiot/lamassuiot/v2/pkg/test/subsystems/storage/postgres"
)

var wPostgres = true

type CAStoreRepoEngine struct {
	repo       storage.CACertificatesRepo
	beforeEach func() error
}

func setupCAStore(t *testing.T) (map[string]CAStoreRepoEngine, func(), error) {
	storageEngines := map[string]CAStoreRepoEngine{}
	cleanupFuncs := []func(){}

	if wPostgres {
		_, postgresSuite := postgres_test.BeforeSuite([]string{"ca"})
		repo, err := postgres.NewCAPostgresRepository(postgresSuite.DB["ca"])
		if err != nil {
			return nil, nil, fmt.Errorf("could not run initialize Postgres CA tables: %s", err)
		}

		cleanupFuncs = append(cleanupFuncs, postgresSuite.AfterSuite)
		storageEngines["POSTGRES"] = CAStoreRepoEngine{
			repo:       repo,
			beforeEach: postgresSuite.BeforeEach,
		}
	}

	cleanup := func() {
		for _, cFunc := range cleanupFuncs {
			cFunc()
		}
	}

	return storageEngines, cleanup, nil
}

func randomCAGenerator() *models.CACertificate {
	issuanceDur, _ := models.ParseDuration("1m")
	caCert, _, _ := helpers.GenerateSelfSignedCA(x509.ECDSA, time.Hour)
	return &models.CACertificate{
		ID: uuid.NewString(),
		Metadata: map[string]interface{}{
			"my-key": "my-val",
		},
		Type:                  models.CertificateTypeManaged,
		Level:                 0,
		CreationTS:            time.Now(),
		IssuanceExpirationRef: models.Expiration{Type: models.Duration, Duration: (*models.TimeDuration)(&issuanceDur)},
		Certificate: models.Certificate{
			SerialNumber:     "",
			Metadata:         map[string]interface{}{},
			Status:           models.StatusActive,
			ValidFrom:        time.Now(),
			ValidTo:          time.Now().Add(time.Hour),
			Type:             models.CertificateTypeManaged,
			EngineID:         "default",
			Certificate:      (*models.X509Certificate)(caCert),
			IssuerCAMetadata: models.IssuerCAMetadata{SerialNumber: caCert.SerialNumber.String()},
			KeyMetadata:      helpers.KeyStrengthMetadataFromCertificate(caCert),
			Subject:          helpers.PkixNameToSubject(caCert.Subject),
		},
	}
}

func TestInsertCAs(t *testing.T) {
	storageEngines, cleanup, err := setupCAStore(t)
	defer func() {
		cleanup()
	}()

	if err != nil {
		t.Fatalf("failed to setup CAStores: %s", err)
	}

	type testcase struct {
		name       string
		beforeEach func() error
		repo       storage.CACertificatesRepo
		preFunc    func(repo storage.CACertificatesRepo)
		runInsert  func(repo storage.CACertificatesRepo) (*models.CACertificate, error)
		check      func(*models.CACertificate, error)
	}

	baseTests := []testcase{
		{
			name:    "OK/INSERT_NEW",
			preFunc: func(repo storage.CACertificatesRepo) {},
			runInsert: func(repo storage.CACertificatesRepo) (*models.CACertificate, error) {
				return repo.Insert(context.Background(), randomCAGenerator())
			},
			check: func(c *models.CACertificate, err error) {
				if err != nil {
					t.Fatalf("got unexpected error: %s", err)
				}
			},
		},
		{
			name: "FAIL/INSERT_DUPLICATE",
			preFunc: func(repo storage.CACertificatesRepo) {
				ca := randomCAGenerator()
				ca.ID = "123"
				repo.Insert(context.Background(), ca)
			},
			runInsert: func(repo storage.CACertificatesRepo) (*models.CACertificate, error) {
				ca := randomCAGenerator()
				ca.ID = "123"
				return repo.Insert(context.Background(), ca)
			},
			check: func(c *models.CACertificate, err error) {
				if err == nil { //should we check for duplicate exception? We should then create a custom error since we need supporting multiple storage engines
					t.Fatalf("expected error, got none")
				}
			},
		},
	}

	testcases := []testcase{}

	for engineName, storage := range storageEngines {
		for _, baseTestcase := range baseTests {
			testcases = append(testcases, testcase{
				name:       fmt.Sprintf("%s/%s", baseTestcase.name, engineName),
				beforeEach: storage.beforeEach,
				preFunc:    baseTestcase.preFunc,
				repo:       storage.repo,
				runInsert:  baseTestcase.runInsert,
				check:      baseTestcase.check,
			})
		}
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			tc.beforeEach()
			tc.preFunc(tc.repo)
			ca, err := tc.runInsert(tc.repo)
			tc.check(ca, err)
		})
	}
}
func TestSelectCAByType(t *testing.T) {
	storageEngines, cleanup, err := setupCAStore(t)
	defer func() {
		cleanup()
	}()

	if err != nil {
		t.Fatalf("failed to setup CAStores: %s", err)
	}

	type testcase struct {
		name       string
		beforeEach func() error
		repo       storage.CACertificatesRepo
		preFunc    func(repo storage.CACertificatesRepo)
		run        func(repo storage.CACertificatesRepo) (map[models.CertificateType][]*models.CACertificate, error)
		check      func(map[models.CertificateType][]*models.CACertificate, error)
	}

	caTypes := []models.CertificateType{models.CertificateTypeExternal, models.CertificateTypeImportedWithKey, models.CertificateTypeManaged}
	basicSelect := func(repo storage.CACertificatesRepo) (map[models.CertificateType][]*models.CACertificate, error) {
		mapList := map[models.CertificateType][]*models.CACertificate{}

		for _, caType := range caTypes {
			list := []*models.CACertificate{}
			_, err := repo.SelectByType(context.Background(), caType, storage.StorageListRequest[models.CACertificate]{
				ExhaustiveRun: true,
				ApplyFunc: func(c models.CACertificate) {
					list = append(list, &c)
				},
				QueryParams: &resources.QueryParameters{},
				ExtraOpts:   map[string]interface{}{},
			})
			if err != nil {
				return mapList, err
			}

			mapList[caType] = list
		}

		return mapList, nil
	}

	baseTests := []testcase{
		{
			name:    "OK/EMPTY_LIST",
			preFunc: func(repo storage.CACertificatesRepo) {},
			run:     basicSelect,
			check: func(mapList map[models.CertificateType][]*models.CACertificate, err error) {
				if err != nil {
					t.Fatalf("got unexpected error: %s", err)
				}

				for _, caType := range caTypes {
					list, hasKey := mapList[caType]

					if !hasKey {
						t.Fatalf("result does not contain list for CA type %s", caType)
					}

					if len(list) != 0 {
						t.Fatalf("unexpected number of elements in list. Expected 0, got %d", len(list))
					}
				}
			},
		},
		{
			name: "OK/SHORT_LIST",
			preFunc: func(repo storage.CACertificatesRepo) {
				ca1 := randomCAGenerator()
				ca1.Type = models.CertificateTypeManaged
				ca1.ID = "managed-1"
				ca2 := randomCAGenerator()
				ca2.Type = models.CertificateTypeManaged
				ca2.ID = "managed-2"
				ca3 := randomCAGenerator()
				ca3.Type = models.CertificateTypeImportedWithKey
				ca3.ID = "imported"
				ca4 := randomCAGenerator()
				ca4.Type = models.CertificateTypeExternal
				ca4.ID = "external"

				cas := []*models.CACertificate{ca1, ca2, ca3, ca4}
				for _, ca := range cas {
					repo.Insert(context.Background(), ca)
				}
			},
			run: basicSelect,
			check: func(mapList map[models.CertificateType][]*models.CACertificate, err error) {
				if err != nil {
					t.Fatalf("got unexpected error: %s", err)
				}

				expectedResults := map[models.CertificateType][]string{
					models.CertificateTypeExternal:        {"external"},
					models.CertificateTypeImportedWithKey: {"imported"},
					models.CertificateTypeManaged:         {"managed-1", "managed-2"},
				}

				for _, caType := range caTypes {
					list, hasKey := mapList[caType]

					if !hasKey {
						t.Fatalf("result does not contain list for CA type %s", caType)
					}

					if len(list) != len(expectedResults[caType]) {
						t.Fatalf("unexpected number of elements in list for CA type %s. Expected %d, got %d", caType, len(expectedResults[caType]), len(list))
					}

					ids := []string{}
					for _, ca := range list {
						ids = append(ids, ca.ID)
					}

					for _, expectedID := range expectedResults[caType] {
						if !slices.Contains(ids, expectedID) {
							t.Fatalf("list does not contain CA with ID %s", expectedID)
						}
					}
				}
			},
		},
		{
			name: "OK/PAGINATE_25_ELEMS/WITH_EXHAUSTIVE_RUN",
			preFunc: func(repo storage.CACertificatesRepo) {
				for i := 0; i < 25; i++ {
					repo.Insert(context.Background(), randomCAGenerator())
				}
			},
			run: func(repo storage.CACertificatesRepo) (map[models.CertificateType][]*models.CACertificate, error) {
				mapList := map[models.CertificateType][]*models.CACertificate{}
				list := []*models.CACertificate{}

				_, err := repo.SelectByType(context.Background(), models.CertificateTypeManaged, storage.StorageListRequest[models.CACertificate]{
					ExhaustiveRun: true,
					ApplyFunc: func(c models.CACertificate) {
						list = append(list, &c)
					},
				})
				if err != nil {
					return nil, err
				}

				mapList[models.CertificateTypeManaged] = list
				return mapList, nil
			},
			check: func(mapList map[models.CertificateType][]*models.CACertificate, err error) {
				if err != nil {
					t.Fatalf("got unexpected error: %s", err)
				}

				if len(mapList[models.CertificateTypeManaged]) != 25 {
					t.Fatalf("unexpected number of elements in list for CA type. Expected 25, got %d", len(mapList[models.CertificateTypeManaged]))
				}
			},
		},
		{
			name: "OK/PAGINATE_25_ELEMS/WITH_BOOKMARK",
			preFunc: func(repo storage.CACertificatesRepo) {
				for i := 0; i < 25; i++ {
					repo.Insert(context.Background(), randomCAGenerator())
				}
			},
			run: func(repo storage.CACertificatesRepo) (map[models.CertificateType][]*models.CACertificate, error) {
				mapList := map[models.CertificateType][]*models.CACertificate{}
				list := []*models.CACertificate{}

				next, err := repo.SelectByType(context.Background(), models.CertificateTypeManaged, storage.StorageListRequest[models.CACertificate]{
					ExhaustiveRun: false,
					QueryParams:   &resources.QueryParameters{PageSize: 10},
					ApplyFunc: func(c models.CACertificate) {
						list = append(list, &c)
					},
				})
				if err != nil {
					return nil, err
				}

				next, err = repo.SelectByType(context.Background(), models.CertificateTypeManaged, storage.StorageListRequest[models.CACertificate]{
					ExhaustiveRun: false,
					QueryParams:   &resources.QueryParameters{NextBookmark: next},
					ApplyFunc: func(c models.CACertificate) {
						list = append(list, &c)
					},
				})
				if err != nil {
					return nil, err
				}

				_, err = repo.SelectByType(context.Background(), models.CertificateTypeManaged, storage.StorageListRequest[models.CACertificate]{
					ExhaustiveRun: false,
					QueryParams:   &resources.QueryParameters{NextBookmark: next},
					ApplyFunc: func(c models.CACertificate) {
						list = append(list, &c)
					},
				})
				if err != nil {
					return nil, err
				}

				mapList[models.CertificateTypeManaged] = list
				return mapList, nil
			},
			check: func(mapList map[models.CertificateType][]*models.CACertificate, err error) {
				if err != nil {
					t.Fatalf("got unexpected error: %s", err)
				}

				if len(mapList[models.CertificateTypeManaged]) != 25 {
					t.Fatalf("unexpected number of elements in list for CA type. Expected 25, got %d", len(mapList[models.CertificateTypeManaged]))
				}
			},
		},
	}

	testcases := []testcase{}

	for engineName, storage := range storageEngines {
		for _, baseTestcase := range baseTests {
			testcases = append(testcases, testcase{
				name:       fmt.Sprintf("%s/%s", baseTestcase.name, engineName),
				beforeEach: storage.beforeEach,
				preFunc:    baseTestcase.preFunc,
				repo:       storage.repo,
				run:        baseTestcase.run,
				check:      baseTestcase.check,
			})
		}
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			tc.beforeEach()
			tc.preFunc(tc.repo)
			ca, err := tc.run(tc.repo)
			tc.check(ca, err)
		})
	}
}

func TestCountCAs(t *testing.T) {
	storageEngines, cleanup, err := setupCAStore(t)
	defer func() {
		cleanup()
	}()

	if err != nil {
		t.Fatalf("failed to setup CAStores: %s", err)
	}

	type testcase struct {
		name       string
		beforeEach func() error
		repo       storage.CACertificatesRepo
		preFunc    func(repo storage.CACertificatesRepo)
		expected   int
	}

	baseTests := []testcase{
		{
			name:     "OK/COUNT_EMPTY",
			expected: 0,
			preFunc:  func(repo storage.CACertificatesRepo) {},
		},
		{
			name:     "OK/COUNT_ONE",
			expected: 1,
			preFunc: func(repo storage.CACertificatesRepo) {
				repo.Insert(context.Background(), randomCAGenerator())
			},
		},
		{
			name:     "OK/COUNT_FIFTY",
			expected: 50,
			preFunc: func(repo storage.CACertificatesRepo) {
				for i := 0; i < 50; i++ {
					repo.Insert(context.Background(), randomCAGenerator())
				}
			},
		},
	}

	testcases := []testcase{}

	for engineName, storage := range storageEngines {
		for _, baseTestcase := range baseTests {
			testcases = append(testcases, testcase{
				name:       fmt.Sprintf("%s/%s", baseTestcase.name, engineName),
				repo:       storage.repo,
				beforeEach: storage.beforeEach,
				preFunc:    baseTestcase.preFunc,
				expected:   baseTestcase.expected,
			})
		}
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			tc.beforeEach()
			tc.preFunc(tc.repo)
			result, err := tc.repo.Count(context.Background())
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}

			if tc.expected != result {
				t.Fatalf("got unexpected value. Expected %d, got %d", tc.expected, result)
			}
		})
	}
}
