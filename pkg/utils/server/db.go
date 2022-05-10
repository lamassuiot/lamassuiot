package server

import (
	"database/sql"
	"fmt"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	migrate "github.com/golang-migrate/migrate/v4"
	migratePostgres "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

func InitializeDBConnection(database string, user string, password string, hostname string, port string, withMigration bool, migrationsFilePath string, logger log.Logger) (*sql.DB, error) {
	connectionString := "dbname=" + database + " user=" + user + " password=" + password + " host=" + hostname + " port=" + port + " sslmode=disable"

	db, err := sql.Open("postgres", connectionString)
	if err != nil {
		return nil, err
	}

	level.Warn(logger).Log("msg", "Connecting to DB")
	err = checkDBAlive(db)

	for err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not start connection with database")
		err = checkDBAlive(db)
	}

	level.Info(logger).Log("msg", "Connection established with Devices database")

	if withMigration {
		driver, err := migratePostgres.WithInstance(db, &migratePostgres.Config{})
		if err != nil {
			level.Error(logger).Log("err", err, "msg", "Could not create postgres migration driver")
			return nil, err
		}

		m, err := migrate.NewWithDatabaseInstance("file://"+migrationsFilePath, "postgres", driver)
		if err != nil {
			level.Error(logger).Log("err", err, "msg", "Could not create db migration instance ")
			return nil, err
		}

		mLogger := newGoKitLogToGoLogAdapter(logger)
		m.Log = mLogger

		m.Up()
		if err != nil {
			level.Error(logger).Log("err", err, "msg", "Could not perform db migration")
			return nil, err
		}
	}

	return db, nil
}

func checkDBAlive(db *sql.DB) error {
	sqlStatement := `
	SELECT WHERE 1=0`
	_, err := db.Query(sqlStatement)
	return err
}

type GoKitLogToStandarLogAdapter interface {
	Printf(format string, v ...interface{})
	Verbose() bool
}

type CustomLogger struct {
	logger log.Logger
}

func newGoKitLogToGoLogAdapter(logger log.Logger) GoKitLogToStandarLogAdapter {
	return &CustomLogger{
		logger: logger,
	}
}

func (l *CustomLogger) Printf(format string, v ...interface{}) {
	level.Debug(l.logger).Log("msg", fmt.Sprintf(format, v))
}
func (l *CustomLogger) Verbose() bool {
	return true
}
