package postgres

import (
	"os"
	"os/exec"
	"testing"
	"time"

	// Sqlite driver based on CGO
	"github.com/lamassuiot/lamassuiot/pkg/v3/config"
	"github.com/lamassuiot/lamassuiot/pkg/v3/helpers"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type testDataModel struct {
	ID    string `gorm:"primaryKey"`
	Name  string
	Grade int
}

func TestCount(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
	}{
		{
			name: "OK/0",
		},
		{
			name: "OK/10",
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

			querier, err := CheckAndCreateTable(dbCli, "testmodel", "id", testDataModel{})
			if err != nil {
				t.Errorf("could not create CA store: %s", err)
			}

			count, err := querier.Count()
			if err != nil {
				t.Errorf("could not count CAs: %s", err)
			}

			if count != 0 {
				t.Errorf("got count %d, want %d", count, 0)
			}
		})
	}
}

func CreateTestPostgresConnection() (*gorm.DB, error) {
	//Launches docker compose
	logger := helpers.ConfigureLogger(logrus.InfoLevel, config.Info, "Postgres")
	cmd := exec.Command("docker-compose", "-f", "./test/docker-compose.yaml", "up")
	cmd.Stderr = os.Stdout

	logger.Infof("launching docker-compose")
	err := cmd.Run()

	if err != nil {
		logger.Errorf("could not launch postgres test docker-compose")
		return nil, err
	}

	logger.Info("launching docker-compose. Sleeping 5s")
	time.Sleep(time.Second * 5)

	dbCli, err := CreatePostgresDBConnection(logger, config.PostgresPSEConfig{
		Hostname: "127.0.0.1",
		Port:     5432,
		Username: "admin",
		Password: "password",
	}, "ca")
	if err != nil {
		logger.Errorf("could not create test postgres connection")
		return nil, err
	}

	return dbCli, nil
}
