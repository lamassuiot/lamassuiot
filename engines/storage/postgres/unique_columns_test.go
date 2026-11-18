package postgres

import (
	"sync"
	"testing"

	"github.com/sirupsen/logrus"
	"gorm.io/gorm/schema"
)

// Exhaustive runs read the last row's unique column values to fetch the next
// batch, so every querier's unique columns must map to a field of its model.
func assertUniqueColumnsResolve[E any](t *testing.T, q *DBQuerier[E]) {
	t.Helper()
	s, err := schema.Parse(new(E), &sync.Map{}, q.NamingStrategy)
	if err != nil {
		t.Fatalf("parse schema: %v", err)
	}
	for _, name := range q.uniqueColumns {
		if s.LookUpField(name) == nil {
			t.Errorf("%s: unique column %q has no field in model %s", q.tableName, name, s.Name)
		}
	}
}

func TestUniqueColumnsResolveToModelFields(t *testing.T) {
	db := dryRunDB(t)
	log := logrus.NewEntry(logrus.New())

	must := func(repo any, err error) any {
		t.Helper()
		if err != nil {
			t.Fatalf("create repository: %v", err)
		}
		return repo
	}

	assertUniqueColumnsResolve(t, must(NewCAPostgresRepository(log, db)).(*PostgresCAStore).querier)
	assertUniqueColumnsResolve(t, must(NewCertificateRepository(log, db)).(*PostgresCertificateStorage).querier)
	assertUniqueColumnsResolve(t, must(NewKMSPostgresRepository(log, db)).(*PostgresKMSStore).querier)
	assertUniqueColumnsResolve(t, must(NewDMSManagerRepository(log, db)).(*PostgresDMSManagerStore).querier)
	assertUniqueColumnsResolve(t, must(NewDeviceManagerRepository(log, db)).(*PostgresDeviceManagerStore).querier)
	assertUniqueColumnsResolve(t, must(NewDeviceGroupsRepository(log, db)).(*PostgresDeviceGroupsStore).querier)
	assertUniqueColumnsResolve(t, must(NewDeviceEventsRepository(log, db)).(*PostgresDeviceEventsStore).querier)
	assertUniqueColumnsResolve(t, must(NewSubscriptionsPostgresRepository(log, db)).(*PostgresSubscriptionsStore).querier)
	assertUniqueColumnsResolve(t, must(NewEventsPostgresRepository(log, db)).(*PostgresEventsStore).querier)
	assertUniqueColumnsResolve(t, must(NewVARepository(log, db)).(*PostgresVAStore).querier)
	assertUniqueColumnsResolve(t, must(NewIssuanceProfileRepository(log, db)).(*PostgresIssuanceStorage).querier)
}
