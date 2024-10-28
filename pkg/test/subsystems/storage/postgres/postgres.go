package postgres_test

import (
	"fmt"
	"os"
	"strconv"

	"github.com/lamassuiot/lamassuiot/v2/core/pkg/test/dockerrunner"
	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormLogger "gorm.io/gorm/logger"
)

const (
	passwd = "test"
)

func RunPostgresDocker(dbs map[string]string) (func() error, *config.PostgresPSEConfig, error) {
	pwd, err := os.Getwd()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get working directory: %s", err)
	}

	createTmpFile := func(fname, content string) (string, error) {
		os.Mkdir(fmt.Sprintf("%s/testdata", pwd), 0755) // #nosec
		initScriptFname := fmt.Sprintf("%s/testdata/%s", pwd, fname)
		err = os.WriteFile(initScriptFname, []byte(content), 0644) // #nosec
		if err != nil {
			return "", err
		}

		return initScriptFname, nil
	}

	idx := 1
	mounts := []docker.HostMount{}

	sqlStatements := ""
	for dbName, dbInitScript := range dbs {
		sqlStatements = sqlStatements + fmt.Sprintf("CREATE DATABASE %s;\n", dbName)
		if dbInitScript != "" {
			initScript := "#!/bin/bash"
			initScript = initScript + fmt.Sprintf("\nset -e")
			initScript = initScript + fmt.Sprintf("\npsql -v ON_ERROR_STOP=1 --username \"$POSTGRES_USER\" --dbname %s <<-EOSQL", dbName)
			initScript = initScript + fmt.Sprintf("\n%s", dbInitScript)
			initScript = initScript + fmt.Sprintf("\nEOSQL")
			fname := fmt.Sprintf("%d_%s.sh", idx, dbName)
			fullpath, err := createTmpFile(fname, initScript)
			if err != nil {
				return nil, nil, err
			}

			mounts = append(mounts, docker.HostMount{
				Type:   "bind",
				Target: "/docker-entrypoint-initdb.d/" + fname,
				Source: fullpath,
			})
		}

		idx++
	}

	initFileName := "0_init.sql"
	initScriptFname, err := createTmpFile(initFileName, sqlStatements)
	if err != nil {
		return nil, nil, err
	}

	mounts = append(mounts, docker.HostMount{
		Type:   "bind",
		Target: "/docker-entrypoint-initdb.d/ " + initFileName,
		Source: initScriptFname,
	})

	containerCleanup, container, dockerHost, err := dockerunner.RunDocker(dockertest.RunOptions{
		Repository: "postgres", // image
		Tag:        "14",       // version
		Env:        []string{"POSTGRES_PASSWORD=" + passwd},
	}, func(hc *docker.HostConfig) {
		hc.Mounts = mounts
		hc.AutoRemove = false
	})
	if err != nil {
		return nil, nil, err
	}

	conStr := fmt.Sprintf("host=localhost port=%s user=postgres dbname=%s password=%s sslmode=disable",
		container.GetPort("5432/tcp"), // get port of localhost
		"postgres",
		passwd,
	)

	var gdb *gorm.DB
	// retry until db server is ready
	err = dockerHost.Retry(func() error {
		gdb, err = gorm.Open(postgres.Open(conStr), &gorm.Config{
			Logger: gormLogger.Discard,
		})
		if err != nil {
			return err
		}
		db, err := gdb.DB()
		if err != nil {
			return err
		}
		return db.Ping()
	})
	if err != nil {
		containerCleanup()
		return nil, nil, err
	}

	p, _ := strconv.Atoi(container.GetPort("5432/tcp"))
	// container is ready, return *gorm.Db for testing
	return containerCleanup, &config.PostgresPSEConfig{
		Hostname: "localhost",
		Port:     p,
		Username: "postgres",
		Password: passwd,
	}, nil
}
