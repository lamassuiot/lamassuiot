//go:build experimental

package couchdb_test

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	cdb_config "github.com/lamassuiot/lamassuiot/engines/storage/couchdb/v3/config"
	hhelpers "github.com/lamassuiot/lamassuiot/shared/http/v3/pkg/helpers"
	dockerunner "github.com/lamassuiot/lamassuiot/shared/subsystems/v3/pkg/test/dockerrunner"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	logger "github.com/sirupsen/logrus"
)

const (
	admin  = "admin"
	passwd = "test"
)

func RunCouchDBDocker() (func() error, *map[string]interface{}, error) {
	containerCleanup, container, dockerHost, err := dockerunner.RunDocker(dockertest.RunOptions{
		Repository: "couchdb", // image
		Tag:        "3.3.3",   // version
		Env:        []string{"COUCHDB_USER=" + admin, "COUCHDB_PASSWORD=" + passwd},
	}, func(hc *docker.HostConfig) {
		hc.PortBindings = map[docker.Port][]docker.PortBinding{
			"5984/tcp": {{HostIP: "", HostPort: "5984"}},
		}
	})
	if err != nil {
		return nil, nil, err
	}

	p, _ := strconv.Atoi(container.GetPort("5984/tcp"))

	address := fmt.Sprintf("%s://%s:%s@%s:%d%s", "http", admin, passwd, "localhost", p, "/_up")
	httpCli, err := hhelpers.BuildHTTPClientWithTLSOptions(&http.Client{}, config.TLSConfig{})
	if err != nil {
		return nil, nil, err
	}

	lCouch := logger.WithField("subsystem-provider", "CouchDB")
	httpCli, err = hhelpers.BuildHTTPClientWithTracerLogger(httpCli, lCouch)
	if err != nil {
		return nil, nil, err
	}

	dockerHost.Retry(func() error {
		resp, err := httpCli.Get(address)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("couchdb not ready yet")
		}
		return nil
	})

	config, err := config.EncodeStruct(&cdb_config.CouchDBPSEConfig{
		HTTPConnection: config.HTTPConnection{
			Protocol: "http",
			BasePath: "/",
			BasicConnection: config.BasicConnection{
				Hostname: "localhost",
				Port:     p,
			},
		},
		Username: admin,
		Password: passwd,
	})
	if err != nil {
		return nil, nil, err
	}

	return containerCleanup, &config, nil

}
