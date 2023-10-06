package postgres_test

import (
	"fmt"
	"strconv"

	"github.com/lamassuiot/lamassuiot/pkg/v3/config"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type PostgresDockerTest struct {
	CleanupDocker func() error
	Db            *gorm.DB
	Config        config.PostgresPSEConfig
}

func NewPostgresDockerTest(dbName string) *PostgresDockerTest {
	// setup *gorm.Db with docker
	cleanupDocker, db, conf := SetupGormWithDocker(dbName)
	return &PostgresDockerTest{
		CleanupDocker: cleanupDocker,
		Config:        conf,
		Db:            db,
	}
}

func (t *PostgresDockerTest) AfterSuite() error {
	return t.CleanupDocker()
}

func (t *PostgresDockerTest) BeforeEach(init func(db *gorm.DB) error) error {
	// clear db tables before each test
	err := t.Db.Exec(`DROP SCHEMA public CASCADE;CREATE SCHEMA public;`).Error
	if err != nil {
		return fmt.Errorf("could not drop all schemas: %s", err)
	}

	return init(t.Db)
}

const (
	passwd = "test"
)

func SetupGormWithDocker(dbName string) (func() error, *gorm.DB, config.PostgresPSEConfig) {
	pool, err := dockertest.NewPool("")
	chk(err)

	runDockerOpt := &dockertest.RunOptions{
		Repository: "postgres", // image
		Tag:        "14",       // version
		Env:        []string{"POSTGRES_PASSWORD=" + passwd, "POSTGRES_DB=" + dbName},
	}

	fnConfig := func(config *docker.HostConfig) {
		config.AutoRemove = true                     // set AutoRemove to true so that stopped container goes away by itself
		config.RestartPolicy = docker.NeverRestart() // don't restart container
	}

	resource, err := pool.RunWithOptions(runDockerOpt, fnConfig)
	chk(err)
	// call clean up function to release resource
	fnCleanup := func() error {
		return resource.Close()
	}

	conStr := fmt.Sprintf("host=localhost port=%s user=postgres dbname=%s password=%s sslmode=disable",
		resource.GetPort("5432/tcp"), // get port of localhost
		dbName,
		passwd,
	)

	var gdb *gorm.DB
	// retry until db server is ready
	err = pool.Retry(func() error {
		gdb, err = gorm.Open(postgres.Open(conStr))
		if err != nil {
			return err
		}
		db, err := gdb.DB()
		if err != nil {
			return err
		}
		return db.Ping()
	})
	chk(err)

	p, _ := strconv.Atoi(resource.GetPort("5432/tcp"))
	// container is ready, return *gorm.Db for testing
	return fnCleanup, gdb, config.PostgresPSEConfig{
		Hostname: "localhost",
		Port:     p,
		Username: "postgres",
		Password: passwd,
	}
}

func chk(err error) {
	if err != nil {
		panic(err)
	}
}
