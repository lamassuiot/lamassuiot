package dockerrunner

import (
	"context"

	"github.com/ory/dockertest/v4"
)

func RunDocker(repository string, opts ...dockertest.RunOption) (func() error, dockertest.ClosableResource, dockertest.ClosablePool, error) {
	ctx := context.Background()
	pool, err := dockertest.NewPool(ctx, "")
	if err != nil {
		return nil, nil, nil, err
	}

	resource, err := pool.Run(ctx, repository, opts...)
	if err != nil {
		pool.Close(ctx)
		return nil, nil, nil, err
	}

	fnCleanup := func() error {
		return resource.Close(ctx)
	}

	return fnCleanup, resource, pool, nil
}
