package oracle

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	authzsdk "github.com/lamassuiot/lamassuiot/v4/connectors/authz/sdk"
	authzgorm "github.com/lamassuiot/lamassuiot/v4/connectors/authz/sdk/gorm"
	coreconfig "github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage/pagination"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
	"github.com/lamassuiot/lamassuiot/v4/engines/storage/oracle/config"
	"github.com/lamassuiot/lamassuiot/v4/engines/storage/oracle/migrations"
	pgstorage "github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres"
	pgconfig "github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres/config"
	"github.com/sirupsen/logrus"
)

func TestOracleKMSPointOperations(t *testing.T) {
	address := os.Getenv("LAMASSU_TEST_ORACLE_CONNECT_STRING")
	if address == "" {
		t.Skip("LAMASSU_TEST_ORACLE_CONNECT_STRING is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	cfg := config.Config{ConnectString: address, Username: os.Getenv("LAMASSU_TEST_ORACLE_USERNAME"), Password: coreconfig.Password(os.Getenv("LAMASSU_TEST_ORACLE_PASSWORD"))}
	pool, err := openDB(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pool.Close() })
	var existing int
	if err := pool.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_tables WHERE table_name IN ('KMS_KEYS','CERTIFICATES','ISSUANCE_PROFILES','VA_ROLE','DMS','EVENTS','SUBSCRIPTIONS','DEVICES','DEVICE_EVENTS','DEVICE_GROUPS','LAMASSU_LOCKS','LAMASSU_SCHEMA_MIGRATIONS','LAMASSU_MIGRATION_LOCK')`).Scan(&existing); err != nil || existing != 0 {
		t.Fatalf("test requires an empty schema: existing=%d error=%v", existing, err)
	}
	if engine, err := NewStorageEngine(ctx, cfg); err == nil {
		_ = engine.Close()
		t.Fatal("engine accepted an unmigrated schema")
	}
	t.Cleanup(func() {
		_, _ = pool.ExecContext(context.Background(), "DROP VIEW certificates_view")
		_, _ = pool.ExecContext(context.Background(), "DROP TYPE lamassu_json_sort_key FORCE")
		for _, name := range []string{"device_groups", "device_events", "devices", "subscriptions", "events", "dms", "va_role", "issuance_profiles", "ca_certificates", "certificates", "kms_keys", "lamassu_locks", "lamassu_schema_migrations", "lamassu_migration_lock"} {
			_, _ = pool.ExecContext(context.Background(), "DROP TABLE "+name+" PURGE")
		}
	})
	plan := migrations.Plan()
	if err := migrations.Apply(ctx, pool, plan); err != nil {
		t.Fatal(err)
	}
	if err := migrations.Apply(ctx, pool, plan); err != nil {
		t.Fatalf("reapply foundation: %v", err)
	}
	RegisterGORMPlugin(authzgorm.NewOracleAuthzGormPlugin())
	engine, err := NewStorageEngine(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	if engine.GetProvider() != coreconfig.Oracle {
		t.Fatal("incorrect engine provider")
	}
	kmsRepo, err := engine.GetKMSStorage()
	if err != nil || kmsRepo == nil {
		t.Fatalf("KMS repository: %v", err)
	}
	deviceRepo, err := engine.GetDeviceStorage()
	if err != nil || deviceRepo == nil {
		t.Fatalf("device repository: %v", err)
	}
	caRepo, err := engine.GetCAStorage()
	if err != nil || caRepo == nil {
		t.Fatalf("CA repository: %v", err)
	}
	certRepo, err := engine.GetCertStorage()
	if err != nil || certRepo == nil {
		t.Fatalf("certificate repository: %v", err)
	}
	vaRepo, err := engine.GetVARoleStorage()
	if err != nil || vaRepo == nil {
		t.Fatalf("VA repository: %v", err)
	}
	guarded := context.WithValue(ctx, authzsdk.AuthzQueryKey, "SELECT * FROM devices WHERE 1=0")
	if count, err := deviceRepo.Count(guarded, nil); err != nil || count != 0 {
		t.Fatalf("deny-all authorization: count=%d error=%v", count, err)
	}
	joinedGrant := context.WithValue(ctx, authzsdk.AuthzQueryKey, `SELECT * FROM devicemanager.devices LEFT JOIN dmsmanager.dms AS j0_0 ON devicemanager.devices.dms_owner = j0_0.id WHERE j0_0.id = 'missing'`)
	if _, err := deviceRepo.Count(joinedGrant, nil); err != nil {
		t.Fatalf("cascading authorization filter: %v", err)
	}
	unsupported := context.WithValue(ctx, authzsdk.AuthzQueryKey, "SELECT * FROM devices JOIN dms ON devices.dms_owner = dms.id WHERE dms.id = 'x'")
	if _, err := deviceRepo.Count(unsupported, nil); !errors.Is(err, authzgorm.ErrAuthorizationUnsupported) {
		t.Fatalf("unsupported authorization guard: %v", err)
	}
	if _, err := deviceRepo.DeviceGroups().SelectAncestors(guarded, "missing"); !errors.Is(err, authzgorm.ErrAuthorizationUnsupported) {
		t.Fatalf("authorization guard on raw query: %v", err)
	}
	db, err := openGORM(pool, registeredPlugins...)
	if err != nil {
		t.Fatal(err)
	}
	testIssuanceProfiles(t, ctx, db)
	testDMS(t, ctx, db)
	testAlerts(t, ctx, db)
	testDevices(t, ctx, db)
	testDeviceGroups(t, ctx, db)
	store := &kmsStore{db: db}
	key := &models.Key{KeyID: "id", EngineID: "engine", Name: "key", HasPrivateKey: true, Algorithm: "RSA", Size: 2048, PublicKey: "public key", CreationTS: time.Now().UTC().Truncate(time.Second), Aliases: []string{"quoted'alias", "other"}, Tags: []string{"tag"}, Metadata: map[string]any{"value": "text", "empty": "", "environment": "production", "critical": true, "rotation_days": 30, "region": "us-east", "tags": []any{"production", "api"}, "ports": []any{8080, 9000}}}
	if _, err := store.Insert(ctx, key); err != nil {
		t.Fatal(err)
	}
	copyInOtherEngine := *key
	copyInOtherEngine.EngineID = "other-engine"
	if _, err := store.Insert(ctx, &copyInOtherEngine); err != nil {
		t.Fatal(err)
	}
	if count, err := store.Count(ctx); err != nil || count != 2 {
		t.Fatalf("count=%d error=%v", count, err)
	}
	pgHost := os.Getenv("LAMASSU_TEST_POSTGRES_HOSTNAME")
	if os.Getenv("CI") != "" && pgHost == "" {
		t.Fatal("CI must configure PostgreSQL for JSONPath parity tests")
	}
	jsonSortRepos := []storage.KMSKeysRepo{store}
	kmsContractRepos := []kmsContractRepository{{name: "oracle", repo: store}}
	caContractRepos := []caContractRepositories{{name: "oracle", kms: kmsRepo, cert: certRepo, ca: caRepo}}
	vaContractRepos := []vaContractRepositories{{name: "oracle", db: db, kms: kmsRepo, cert: certRepo, va: vaRepo}}
	if pgHost != "" {
		logger := logrus.NewEntry(logrus.New())
		pgCfg := pgconfig.PostgresPSEConfig{
			Hostname: pgHost, Port: 5432, Username: os.Getenv("LAMASSU_TEST_POSTGRES_USERNAME"),
			Password: coreconfig.Password(os.Getenv("LAMASSU_TEST_POSTGRES_PASSWORD")),
		}
		if err := pgstorage.MigrateDatabase(logger, pgCfg, pgstorage.KMS_SCHEMA); err != nil {
			t.Fatalf("migrate PostgreSQL KMS schema for JSONPath parity: %v", err)
		}
		pgDB, err := pgstorage.CreatePostgresDBConnection(logger, pgCfg, pgstorage.KMS_SCHEMA)
		if err != nil {
			t.Fatalf("connect to PostgreSQL KMS schema for JSONPath parity: %v", err)
		}
		if sqlDB, err := pgDB.DB(); err == nil {
			t.Cleanup(func() { _ = sqlDB.Close() })
		}
		pgRepo, err := pgstorage.NewKMSPostgresRepository(logger, pgDB)
		if err != nil {
			t.Fatalf("create PostgreSQL KMS repository for JSONPath parity: %v", err)
		}
		jsonSortRepos = append(jsonSortRepos, pgRepo)
		kmsContractRepos = append(kmsContractRepos, kmsContractRepository{name: "postgres", repo: pgRepo})
		if err := pgstorage.MigrateDatabase(logger, pgCfg, pgstorage.CA_SCHEMA); err != nil {
			t.Fatalf("migrate PostgreSQL CA schema for repository parity: %v", err)
		}
		pgCADB, err := pgstorage.CreatePostgresDBConnection(logger, pgCfg, pgstorage.CA_SCHEMA)
		if err != nil {
			t.Fatalf("connect to PostgreSQL CA schema for repository parity: %v", err)
		}
		if sqlDB, err := pgCADB.DB(); err == nil {
			t.Cleanup(func() { _ = sqlDB.Close() })
		}
		pgCertRepo, err := pgstorage.NewCertificateRepository(logger, pgCADB)
		if err != nil {
			t.Fatalf("create PostgreSQL certificate repository: %v", err)
		}
		pgCARepo, err := pgstorage.NewCAPostgresRepository(logger, pgCADB)
		if err != nil {
			t.Fatalf("create PostgreSQL CA repository: %v", err)
		}
		caContractRepos = append(caContractRepos, caContractRepositories{name: "postgres", kms: pgRepo, cert: pgCertRepo, ca: pgCARepo})
		if err := pgstorage.MigrateDatabase(logger, pgCfg, pgstorage.VA_SCHEMA); err != nil {
			t.Fatalf("migrate PostgreSQL VA schema for repository parity: %v", err)
		}
		pgVADB, err := pgstorage.CreatePostgresDBConnection(logger, pgCfg, pgstorage.VA_SCHEMA)
		if err != nil {
			t.Fatalf("connect to PostgreSQL VA schema for repository parity: %v", err)
		}
		if sqlDB, err := pgVADB.DB(); err == nil {
			t.Cleanup(func() { _ = sqlDB.Close() })
		}
		pgVARepo, err := pgstorage.NewVARepository(logger, pgVADB)
		if err != nil {
			t.Fatalf("create PostgreSQL VA repository: %v", err)
		}
		vaContractRepos = append(vaContractRepos, vaContractRepositories{name: "postgres", db: pgVADB, kms: pgRepo, cert: pgCertRepo, va: pgVARepo})
	}
	testJSONPathFilterContract(t, ctx, jsonSortRepos...)
	testOracleJSONPathSort(t, ctx, jsonSortRepos...)
	testKMSRepositoryContracts(t, ctx, kmsContractRepos...)
	testCAAndCertificateContracts(t, ctx, caContractRepos...)
	testVARepositoryContracts(t, ctx, vaContractRepos...)
	var jsonPathKeys []string
	_, err = store.SelectAll(ctx, storage.StorageListRequest[models.Key]{
		QueryParams: &resources.QueryParameters{PageSize: 10, Filters: []resources.FilterOption{
			{Field: "key_id", FilterOperation: resources.StringEqual, Value: "id"},
			{Field: "metadata", FilterOperation: resources.JsonPathExpression, Value: `$.rotation_days > 20`},
		}},
		ExhaustiveRun: true,
		ApplyFunc:     func(item models.Key) { jsonPathKeys = append(jsonPathKeys, item.EngineID) },
	})
	if err != nil || !reflect.DeepEqual(jsonPathKeys, []string{"engine", "other-engine"}) {
		t.Fatalf("JSONPath list=%v error=%v", jsonPathKeys, err)
	}
	if keys, err := store.SelectByKeyID(ctx, "id"); err != nil || len(keys) != 2 || keys[0].EngineID != "engine" || keys[1].EngineID != "other-engine" {
		t.Fatalf("key copies: %+v error=%v", keys, err)
	}
	for _, tc := range []struct {
		filter resources.FilterOption
		count  int
	}{
		{resources.FilterOption{Field: "name", FilterOperation: resources.StringEqualIgnoreCase, Value: "KEY"}, 2},
		{resources.FilterOption{Field: "name", FilterOperation: resources.StringContains, Value: "%"}, 0},
		{resources.FilterOption{Field: "name", FilterOperation: resources.StringContainsIgnoreCase, Value: "KE"}, 2},
		{resources.FilterOption{Field: "size", FilterOperation: resources.NumberGreaterOrEqualThan, Value: "2048"}, 2},
		{resources.FilterOption{Field: "tags", FilterOperation: resources.StringArrayContains, Value: "tag"}, 2},
		{resources.FilterOption{Field: "aliases", FilterOperation: resources.StringArrayContains, Value: "quoted'alias"}, 2},
		{resources.FilterOption{Field: "engine_id", FilterOperation: resources.StringIn, Value: "engine,other-engine"}, 2},
	} {
		params := &resources.QueryParameters{Filters: []resources.FilterOption{
			{Field: "key_id", FilterOperation: resources.StringEqual, Value: "id"},
			tc.filter,
		}}
		count, err := store.CountWithFilters(ctx, params)
		if err != nil || count != tc.count {
			t.Errorf("filter %+v: count=%d error=%v", tc.filter, count, err)
		}
	}
	if count, err := store.CountByEngineWithFilters(ctx, "engine", nil); err != nil || count != 1 {
		t.Fatalf("engine count=%d error=%v", count, err)
	}
	if count, err := store.CountByEngineWithFilters(ctx, "", nil); err != nil || count != 0 {
		t.Fatalf("empty engine count=%d error=%v", count, err)
	}
	if _, err := store.CountWithFilters(ctx, &resources.QueryParameters{Filters: []resources.FilterOption{{Field: "name) OR 1=1 --", FilterOperation: resources.StringEqual, Value: "key"}}}); err == nil {
		t.Fatal("accepted invalid filter field")
	}
	params := &resources.QueryParameters{PageSize: 1, Sort: resources.SortOptions{SortField: "name", SortMode: resources.SortModeAsc}, Filters: []resources.FilterOption{{Field: "name", FilterOperation: resources.StringEqual, Value: "key"}}}
	var pages []string
	bookmark, err := store.SelectAll(ctx, storage.StorageListRequest[models.Key]{QueryParams: params, ApplyFunc: func(key models.Key) { pages = append(pages, key.EngineID) }})
	if err != nil || bookmark == "" {
		t.Fatalf("first page: bookmark=%q error=%v", bookmark, err)
	}
	params.NextBookmark = bookmark
	bookmark, err = store.SelectAll(ctx, storage.StorageListRequest[models.Key]{QueryParams: params, ApplyFunc: func(key models.Key) { pages = append(pages, key.EngineID) }})
	if err != nil || bookmark != "" || !reflect.DeepEqual(pages, []string{"engine", "other-engine"}) {
		t.Fatalf("second page: keys=%v bookmark=%q error=%v", pages, bookmark, err)
	}
	badBookmark := (pagination.Page{Limit: 1, Sort: resources.SortOptions{SortField: "name; DROP TABLE kms_keys", SortMode: resources.SortModeAsc}}).Next()
	if _, err := store.SelectAll(ctx, storage.StorageListRequest[models.Key]{QueryParams: &resources.QueryParameters{NextBookmark: badBookmark}, ApplyFunc: func(models.Key) {}}); err == nil {
		t.Fatal("accepted unsafe bookmark sort")
	}
	params.NextBookmark = ""
	unmatched := *key
	unmatched.KeyID, unmatched.Name = "zz", "excluded"
	if _, err := store.Insert(ctx, &unmatched); err != nil {
		t.Fatal(err)
	}
	var exhaustive []string
	var updateErr error
	_, err = store.SelectAll(ctx, storage.StorageListRequest[models.Key]{ExhaustiveRun: true, QueryParams: params, ApplyFunc: func(item models.Key) {
		exhaustive = append(exhaustive, item.EngineID)
		item.Name = "changed"
		if _, err := store.Update(ctx, &item); err != nil {
			updateErr = err
		}
	}})
	if err != nil || updateErr != nil || !reflect.DeepEqual(exhaustive, []string{"engine", "other-engine"}) {
		t.Fatalf("exhaustive=%v error=%v update=%v", exhaustive, err, updateErr)
	}
	if err := store.Delete(ctx, "zz", "engine"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.ExecContext(ctx, `UPDATE kms_keys SET name = 'key'`); err != nil {
		t.Fatal(err)
	}
	found, read, err := store.SelectExistsByKeyID(ctx, "id", "engine")
	readMetadata, readMetadataErr := json.Marshal(read.Metadata)
	expectedMetadata, expectedMetadataErr := json.Marshal(key.Metadata)
	if err != nil || readMetadataErr != nil || expectedMetadataErr != nil || !found || !read.HasPrivateKey || !reflect.DeepEqual(read.Aliases, key.Aliases) || string(readMetadata) != string(expectedMetadata) {
		t.Fatalf("select: found=%v key=%+v err=%v", found, read, err)
	}
	found, read, err = store.SelectExistsByAlias(ctx, "quoted'alias")
	if err != nil || !found || read.KeyID != key.KeyID {
		t.Fatalf("alias: found=%v key=%+v err=%v", found, read, err)
	}
	if found, _, err := store.SelectExistsByAlias(ctx, "quoted'alias' OR 1=1 --"); err != nil || found {
		t.Fatalf("unexpected alias match: %v %v", found, err)
	}
	key.HasPrivateKey = false
	key.Tags = []string{}
	if _, err := store.Update(ctx, key); err != nil {
		t.Fatal(err)
	}
	_, read, err = store.SelectExistsByKeyID(ctx, "id", "engine")
	if err != nil || read.HasPrivateKey || len(read.Tags) != 0 {
		t.Fatalf("update: %+v %v", read, err)
	}
	if _, err := pool.ExecContext(ctx, `INSERT INTO certificates (serial_number, key_id, engine_id) VALUES ('one', 'id', 'engine')`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.ExecContext(ctx, `INSERT INTO certificates (serial_number, key_id, engine_id) VALUES ('missing', 'absent', 'engine')`); err == nil {
		t.Fatal("accepted a certificate with a missing key")
	}
	if _, err := pool.ExecContext(ctx, `INSERT INTO certificates (serial_number, key_id) VALUES ('noengine', 'id')`); err == nil {
		t.Fatal("accepted a key reference without an engine")
	}
	var hasPrivateKey int
	if err := pool.QueryRowContext(ctx, `SELECT has_private_key FROM certificates_view WHERE serial_number = 'one'`).Scan(&hasPrivateKey); err != nil || hasPrivateKey != 0 {
		t.Fatalf("public-only certificate: has_private_key=%d err=%v", hasPrivateKey, err)
	}
	if _, err := pool.ExecContext(ctx, `UPDATE kms_keys SET has_private_key = 1 WHERE key_id = 'id' AND engine_id = 'engine'`); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRowContext(ctx, `SELECT has_private_key FROM certificates_view WHERE serial_number = 'one'`).Scan(&hasPrivateKey); err != nil || hasPrivateKey != 1 {
		t.Fatalf("private certificate: has_private_key=%d err=%v", hasPrivateKey, err)
	}
	if _, err := pool.ExecContext(ctx, `INSERT INTO ca_certificates (serial_number, id) VALUES ('one', 'ca-id')`); err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "device"}, NotBefore: now, NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	certificate := models.Certificate{SerialNumber: "two", Certificate: (*models.X509Certificate)(parsed), Subject: models.Subject{CommonName: "device"}, Status: models.StatusActive, KeyID: "id", EngineID: "engine", ValidFrom: now, ValidTo: now.Add(time.Hour), RevocationTimestamp: now, KeyMetadata: models.KeyStrengthMetadata{Type: models.KeyType(x509.Ed25519), Bits: 256, Strength: models.KeyStrengthHigh}, Extensions: models.CertificateExtensions{KeyUsage: models.X509KeyUsage(x509.KeyUsageDigitalSignature)}, Metadata: map[string]any{"purpose": "test"}}
	certificate.IssuerCAMetadata.ID = "issuer-ca"
	certStore := &certificateStore{db: db}
	if _, err := certStore.Insert(ctx, &certificate); err != nil {
		t.Fatal(err)
	}
	if found, stored, err := certStore.SelectExistsBySerialNumber(ctx, "two"); err != nil || !found || stored.Certificate == nil || !reflect.DeepEqual(stored.Certificate.Raw, der) || !stored.HasPrivateKey || stored.KeyID != "id" || stored.Subject.CommonName != "device" || stored.Metadata["purpose"] != "test" {
		t.Fatalf("certificate round trip: found=%v certificate=%+v err=%v", found, stored, err)
	}
	testVARoles(t, ctx, db, certStore, now)
	directCARepo := &caStore{db: db}
	ca := &models.CACertificate{ID: "ca-two", CertificateSerialNumber: "two", CreationTS: now, Level: 2, ProfileID: "profile", Metadata: map[string]any{"owner": "test"}}
	if created, err := directCARepo.Insert(ctx, ca); err != nil || created.Certificate.SerialNumber != "two" || !created.Certificate.HasPrivateKey {
		t.Fatalf("insert CA: %+v error=%v", created, err)
	}
	duplicateCA := *ca
	if _, err := directCARepo.Insert(ctx, &duplicateCA); !errors.Is(err, errs.ErrCAAlreadyExists) {
		t.Fatalf("duplicate CA: %v", err)
	}
	ca.Certificate.Subject.CommonName = "should not be saved"
	ca.Level = 3
	if updated, err := directCARepo.Update(ctx, ca); err != nil || updated.Level != 3 || updated.Certificate.Subject.CommonName != "device" {
		t.Fatalf("update CA: %+v error=%v", updated, err)
	}
	caFilter := &resources.QueryParameters{Sort: resources.SortOptions{SortField: "subject.common_name", SortMode: resources.SortModeAsc}, Filters: []resources.FilterOption{{Field: "subject.common_name", FilterOperation: resources.StringEqual, Value: "device"}}}
	if count, err := directCARepo.CountByEngineWithFilters(ctx, "engine", caFilter); err != nil || count != 1 {
		t.Fatalf("CA count=%d error=%v", count, err)
	}
	var matchedCAs []string
	caReq := storage.StorageListRequest[models.CACertificate]{QueryParams: caFilter, ApplyFunc: func(c models.CACertificate) { matchedCAs = append(matchedCAs, c.ID) }}
	if _, err := directCARepo.SelectBySubjectAndSubjectKeyID(ctx, models.Subject{CommonName: "device"}, "", caReq); err != nil || !reflect.DeepEqual(matchedCAs, []string{"ca-two"}) {
		t.Fatalf("CA subject matches=%v error=%v", matchedCAs, err)
	}
	third := certificate
	third.SerialNumber = "three"
	if _, err := certStore.Insert(ctx, &third); err != nil {
		t.Fatal(err)
	}
	if n, err := certStore.CountByCAIDAndStatus(ctx, "issuer-ca", models.StatusActive); err != nil || n != 2 {
		t.Fatalf("certificate count=%d error=%v", n, err)
	}
	certParams := &resources.QueryParameters{PageSize: 1, Filters: []resources.FilterOption{{Field: "subject.common_name", FilterOperation: resources.StringEqual, Value: "device"}}}
	var serials []string
	certReq := storage.StorageListRequest[models.Certificate]{QueryParams: certParams, ApplyFunc: func(c models.Certificate) { serials = append(serials, c.SerialNumber) }}
	certBookmark, err := certStore.SelectByCA(ctx, "issuer-ca", certReq)
	if err != nil || certBookmark == "" {
		t.Fatalf("first certificate page: bookmark=%q error=%v", certBookmark, err)
	}
	certParams.NextBookmark = certBookmark
	certBookmark, err = certStore.SelectByCA(ctx, "issuer-ca", certReq)
	if err != nil || certBookmark != "" || !reflect.DeepEqual(serials, []string{"three", "two"}) {
		t.Fatalf("certificate pages=%v bookmark=%q error=%v", serials, certBookmark, err)
	}
	var expiring []string
	if _, err := certStore.SelectByExpirationDate(ctx, now.Add(2*time.Hour), now.Add(-time.Hour), storage.StorageListRequest[models.Certificate]{ApplyFunc: func(c models.Certificate) { expiring = append(expiring, c.SerialNumber) }}); err != nil || !reflect.DeepEqual(expiring, []string{"three", "two"}) {
		t.Fatalf("expiring=%v error=%v", expiring, err)
	}
	certParams.NextBookmark = ""
	var traversed []string
	var certUpdateErr error
	_, err = certStore.SelectByCA(ctx, "issuer-ca", storage.StorageListRequest[models.Certificate]{QueryParams: certParams, ExhaustiveRun: true, ApplyFunc: func(c models.Certificate) {
		traversed = append(traversed, c.SerialNumber)
		c.Subject.CommonName = "processed"
		if _, err := certStore.Update(ctx, &c); err != nil {
			certUpdateErr = err
		}
	}})
	if err != nil || certUpdateErr != nil || !reflect.DeepEqual(traversed, []string{"three", "two"}) {
		t.Fatalf("exhaustive certificates=%v error=%v update=%v", traversed, err, certUpdateErr)
	}
	if err := certStore.Delete(ctx, "three"); err != nil {
		t.Fatal(err)
	}
	duplicate := certificate
	if _, err := certStore.Insert(ctx, &duplicate); !errors.Is(err, errs.ErrCertificateAlreadyExists) {
		t.Fatalf("duplicate certificate: %v", err)
	}
	missingKey := certificate
	missingKey.SerialNumber, missingKey.KeyID = "missing-key", "absent"
	if _, err := certStore.Insert(ctx, &missingKey); !errors.Is(err, errs.ErrKeyNotFound) {
		t.Fatalf("certificate with missing key: %v", err)
	}
	certificate.Subject.CommonName = "updated device"
	if updated, err := certStore.Update(ctx, &certificate); err != nil || updated.Subject.CommonName != "updated device" || !updated.HasPrivateKey {
		t.Fatalf("update certificate: %+v error=%v", updated, err)
	}
	if err := certStore.ReleaseKey(ctx, []string{"two"}); err != nil {
		t.Fatal(err)
	}
	if found, stored, err := certStore.SelectExistsBySerialNumber(ctx, "two"); err != nil || !found || stored.KeyID != "" || stored.HasPrivateKey {
		t.Fatalf("released key: found=%v cert=%+v error=%v", found, stored, err)
	}
	called := false
	if err := store.DeleteWith(ctx, "id", "engine", func() error { called = true; return nil }); !errors.Is(err, errs.ErrKeyInUse) || called {
		t.Fatalf("referenced key: callback=%v err=%v", called, err)
	}
	if _, err := pool.ExecContext(ctx, `DELETE FROM certificates WHERE serial_number = 'one'`); err != nil {
		t.Fatal(err)
	}
	if err := certStore.Delete(ctx, "two"); err != nil {
		t.Fatal(err)
	}
	var caCount int
	if err := pool.QueryRowContext(ctx, `SELECT COUNT(*) FROM ca_certificates WHERE id = 'ca-id'`).Scan(&caCount); err != nil || caCount != 0 {
		t.Fatalf("CA cascade count=%d err=%v", caCount, err)
	}
	callbackErr := errors.New("callback failed")
	if err := store.DeleteWith(ctx, "id", "engine", func() error { return callbackErr }); !errors.Is(err, callbackErr) {
		t.Fatalf("callback error: %v", err)
	}
	if found, _, err := store.SelectExistsByKeyID(ctx, "id", "engine"); err != nil || !found {
		t.Fatalf("rollback: found=%v err=%v", found, err)
	}
	if err := store.DeleteWith(ctx, "id", "engine", func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if renamed, err := store.RenameKey(ctx, "other-engine", "id", "renamed", func() error { return nil }); err != nil || !renamed {
		t.Fatalf("rename on migrated schema: renamed=%v error=%v", renamed, err)
	}
	if found, renamed, err := store.SelectExistsByKeyID(ctx, "renamed", "other-engine"); err != nil || !found || len(renamed.Aliases) == 0 || renamed.Aliases[len(renamed.Aliases)-1] != "id" {
		t.Fatalf("renamed key: found=%v key=%+v error=%v", found, renamed, err)
	}
	if err := store.Delete(ctx, "renamed", "other-engine"); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteWith(ctx, "id", "engine", func() error { t.Fatal("callback for missing key"); return nil }); !errors.Is(err, errs.ErrKeyNotFound) {
		t.Fatalf("missing key: %v", err)
	}
}

func testJSONPathFilterContract(t *testing.T, ctx context.Context, repos ...storage.KMSKeysRepo) {
	t.Helper()
	metadata := map[string]any{
		"value": "text", "empty": "", "environment": "production", "critical": true,
		"rotation_days": 30, "large_number": int64(9007199254740993), "region": "us-east",
		"tags": []any{"production", "api"}, "ports": []any{8080, 9000}, "nullable": nil,
		"rank_empty_array": []any{}, "rank_array": []any{1},
	}
	for _, repo := range repos {
		for _, engineID := range []string{"filter-one", "filter-two"} {
			if _, err := repo.Insert(ctx, &models.Key{
				KeyID: "json-filter", EngineID: engineID, Name: "json-filter", Algorithm: "RSA", Size: 2048,
				PublicKey: "public key", CreationTS: time.Now().UTC().Truncate(time.Second),
				Aliases: []string{}, Tags: []string{}, Metadata: metadata,
			}); err != nil {
				t.Fatalf("insert JSON filter fixture %s: %v", engineID, err)
			}
		}
	}
	t.Cleanup(func() {
		for _, repo := range repos {
			for _, engineID := range []string{"filter-one", "filter-two"} {
				if err := repo.Delete(context.Background(), "json-filter", engineID); err != nil {
					t.Errorf("delete JSON filter fixture %s: %v", engineID, err)
				}
			}
		}
	})
	for _, tc := range []struct {
		expression string
		want       int
	}{
		{`$.value == "text"`, 2},
		{`$.rank_empty_array < null`, 0},
		{`$.rank_empty_array < "a"`, 0},
		{`$.rank_empty_array > null`, 0},
		{`$.rank_array > true`, 0},
		{`$.value != "other"`, 2},
		{`!($.value == "text")`, 0},
		{`!($.value == "other")`, 2},
		{`!($.value == 1)`, 0},
		{`!($.nullable == "x")`, 2},
		{`!($.missing == "x")`, 2},
		{`!($.missing == "x" || $.value == "text")`, 0},
		{`!($.value == "other" && $.missing == "x")`, 2},
		{`!($.missing starts with "x")`, 2},
		{`!($.value starts with "z")`, 2},
		{`$.empty == ""`, 2},
		{`$.critical == true && $.rotation_days >= 30`, 2},
		{`$.rotation_days < 31 && $.rotation_days <= 30`, 2},
		{`$.rotation_days != 1`, 2},
		{`$.large_number == 9007199254740993`, 2},
		{`$.value == "no" || $.region starts with "us-"`, 2},
		{`$.critical == true && exists($.environment)`, 2},
		{`exists($.nullable) && $.nullable == null`, 2},
		{`exists($.tags[*] ? (@ == "production"))`, 2},
		{`exists($.ports[*] ? (@ > 8000))`, 2},
		{`$.environment like_regex "^prod"`, 2},
		{`$.value like_regex "TEXT" flag "i"`, 2},
		{`$.value like_regex "TEXT" flag "iq"`, 2},
		{`$.value like_regex "text" flag "q"`, 2},
		{`$.value like_regex "^te" flag "qm"`, 0},
		{`$.value like_regex "t.xt" flag "qs"`, 0},
		{`$.tags.type() == "array"`, 2},
		{`$.type() == "object"`, 2},
		{`$.critical > 1`, 0},
		{`$.value == 1`, 0},
		{`$.value like_regex "t.xt" flag "q"`, 0},
		{`$.value like_regex "T.XT" flag "qi"`, 0},
		{`exists($.missing)`, 0},
		{`$.missing == ""`, 0},
	} {
		for i, repo := range repos {
			query := &resources.QueryParameters{Filters: []resources.FilterOption{
				{Field: "key_id", FilterOperation: resources.StringEqual, Value: "json-filter"},
				{Field: "metadata", FilterOperation: resources.JsonPathExpression, Value: tc.expression},
			}}
			count, err := repo.CountWithFilters(ctx, query)
			if err != nil || count != tc.want {
				t.Errorf("JSONPath repository %d expression %q: count=%d want=%d error=%v", i, tc.expression, count, tc.want, err)
			}
		}
	}
	// These are Oracle-supported JSONPath constructs that PostgreSQL's parser
	// rejects, so exercise them against Oracle without treating them as shared
	// PostgreSQL parity cases.
	for _, tc := range []struct {
		expression string
		want       int
	}{
		{`$.value in ("text", "other")`, 2},
		{`$.region has substring "east"`, 2},
		{`$.rotation_days.number() > 20`, 2},
	} {
		query := &resources.QueryParameters{Filters: []resources.FilterOption{
			{Field: "key_id", FilterOperation: resources.StringEqual, Value: "json-filter"},
			{Field: "metadata", FilterOperation: resources.JsonPathExpression, Value: tc.expression},
		}}
		count, err := repos[0].CountWithFilters(ctx, query)
		if err != nil || count != tc.want {
			t.Errorf("Oracle-only JSONPath expression %q: count=%d want=%d error=%v", tc.expression, count, tc.want, err)
		}
	}
}

func testOracleJSONPathSort(t *testing.T, ctx context.Context, repos ...storage.KMSKeysRepo) {
	t.Helper()
	probes := []struct {
		engineID string
		metadata map[string]any
	}{
		{engineID: "sort-missing", metadata: map[string]any{"other": true}},
		{engineID: "sort-null", metadata: map[string]any{"value": nil}},
		{engineID: "sort-empty", metadata: map[string]any{"value": ""}},
		{engineID: "sort-number", metadata: map[string]any{"value": 2}},
		{engineID: "sort-date", metadata: map[string]any{"value": "2025-01-01T00:00:00Z"}},
		{engineID: "sort-date-low", metadata: map[string]any{"value": "2025-01-01T00:00:00.0000004Z"}},
		{engineID: "sort-date-up", metadata: map[string]any{"value": "2025-01-01T00:00:00.0000005Z"}},
		{engineID: "sort-array", metadata: map[string]any{"value": []int{1}}},
		{engineID: "sort-array-long", metadata: map[string]any{"value": []string{strings.Repeat("a", 5000)}}},
		{engineID: "sort-text", metadata: map[string]any{"value": "alpha"}},
		{engineID: "sort-object", metadata: map[string]any{"value": map[string]int{"a": 1}}},
		{engineID: "sort-object-long", metadata: map[string]any{"value": map[string]string{"a": strings.Repeat("a", 5000)}}},
	}
	for _, repo := range repos {
		for _, probe := range probes {
			if _, err := repo.Insert(ctx, &models.Key{
				KeyID: "json-sort", EngineID: probe.engineID, Name: "json-sort", Algorithm: "RSA", Size: 2048,
				PublicKey: "public key", CreationTS: time.Now().UTC().Truncate(time.Second),
				Aliases: []string{}, Tags: []string{}, Metadata: probe.metadata,
			}); err != nil {
				t.Fatalf("insert JSON sort probe %s: %v", probe.engineID, err)
			}
		}
	}
	t.Cleanup(func() {
		for _, repo := range repos {
			for _, probe := range probes {
				if err := repo.Delete(context.Background(), "json-sort", probe.engineID); err != nil {
					t.Errorf("delete JSON sort probe %s: %v", probe.engineID, err)
				}
			}
		}
	})
	params := &resources.QueryParameters{
		PageSize: 20,
		Sort:     resources.SortOptions{SortField: "metadata", SortMode: resources.SortModeAsc, JsonPathExpr: "$.value"},
		Filters:  []resources.FilterOption{{Field: "engine_id", FilterOperation: resources.StringIn, Value: "sort-missing,sort-null,sort-empty,sort-number,sort-date,sort-date-low,sort-date-up,sort-array-long,sort-array,sort-text,sort-object-long,sort-object"}},
	}
	expected := []string{"sort-missing", "sort-null", "sort-empty", "sort-number", "sort-date", "sort-date-low", "sort-date-up", "sort-array-long", "sort-array", "sort-text", "sort-object-long", "sort-object"}
	for i, repo := range repos {
		var actual []string
		_, err := repo.SelectAll(ctx, storage.StorageListRequest[models.Key]{
			QueryParams: params,
			ApplyFunc:   func(item models.Key) { actual = append(actual, item.EngineID) },
		})
		if err != nil || !reflect.DeepEqual(actual, expected) {
			t.Fatalf("JSONPath sort repository %d: got %v, want %v, error=%v", i, actual, expected, err)
		}
	}
}
