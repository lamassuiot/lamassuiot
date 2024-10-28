package dockerunner

import (
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
)

func RunDocker(options dockertest.RunOptions, hcOpts func(*docker.HostConfig)) (func() error, *dockertest.Resource, *dockertest.Pool, error) {
	pool, err := dockertest.NewPool("")
	if err != nil {
		return nil, nil, nil, err
	}

	fnConfig := func(config *docker.HostConfig) {
		config.AutoRemove = true                     // set AutoRemove to true so that stopped container goes away by itself
		config.RestartPolicy = docker.NeverRestart() // don't restart container
	}

	resource, err := pool.RunWithOptions(&options, fnConfig, hcOpts)
	if err != nil {
		return nil, nil, nil, err
	}

	// call clean up function to release resource
	fnCleanup := func() error {
		err := resource.Close()
		if err != nil {
			return err
		}

		return nil
	}

	return fnCleanup, resource, pool, nil
}
