package postgrestest

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"time"

	"github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3/config"
	dockerrunner "github.com/lamassuiot/lamassuiot/shared/subsystems/v3/pkg/test/dockerrunner"
	mobycontainer "github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/api/types/network"
	"github.com/ory/dockertest/v4"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormLogger "gorm.io/gorm/logger"
)

const (
	passwd = "test"
)

func RunPostgresDocker(dbs map[string]string, exposeAsStandardPort bool) (func() error, *config.PostgresPSEConfig, error) {
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
	mounts := []mount.Mount{}

	sqlStatements := ""
	for dbName, dbInitScript := range dbs {
		sqlStatements = sqlStatements + fmt.Sprintf("CREATE DATABASE %s;\n", dbName)
		if dbInitScript != "" {
			initScript := "#!/bin/bash"
			initScript = initScript + "\nset -e"
			initScript = initScript + fmt.Sprintf("\npsql -v ON_ERROR_STOP=1 --username \"$POSTGRES_USER\" --dbname %s <<-EOSQL", dbName)
			initScript = initScript + fmt.Sprintf("\n%s", dbInitScript)
			initScript = initScript + "\nEOSQL"
			fname := fmt.Sprintf("%d_%s.sh", idx, dbName)
			fullpath, err := createTmpFile(fname, initScript)
			if err != nil {
				return nil, nil, err
			}

			mounts = append(mounts, mount.Mount{
				Type:   mount.TypeBind,
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

	mounts = append(mounts, mount.Mount{
		Type:   mount.TypeBind,
		Target: "/docker-entrypoint-initdb.d/ " + initFileName,
		Source: initScriptFname,
	})

	runOpts := []dockertest.RunOption{
		dockertest.WithTag("14"),
		dockertest.WithEnv([]string{"POSTGRES_PASSWORD=" + passwd}),
		dockertest.WithLabels(map[string]string{
			"group": "lamassuiot-monolithic",
		}),
		dockertest.WithHostConfig(func(hc *mobycontainer.HostConfig) {
			hc.Mounts = mounts
			hc.AutoRemove = false
		}),
	}
	if exposeAsStandardPort {
		runOpts = append(runOpts, dockertest.WithPortBindings(network.PortMap{
			network.MustParsePort("5432/tcp"): []network.PortBinding{
				{HostIP: netip.MustParseAddr("0.0.0.0"), HostPort: "5432"},
			},
		}))
	}

	containerCleanup, container, dockerHost, err := dockerrunner.RunDocker("postgres", runOpts...)
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
	err = dockerHost.Retry(context.Background(), 30*time.Second, func() error {
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
