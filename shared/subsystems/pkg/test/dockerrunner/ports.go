package dockerrunner

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/moby/moby/api/types/network"
	mobyclient "github.com/moby/moby/client"
)

// ContainerInspector supplies fresh Docker container state.
type ContainerInspector interface {
	ContainerInspect(context.Context, string, mobyclient.ContainerInspectOptions) (mobyclient.ContainerInspectResult, error)
}

// WaitForPublishedPort waits up to 30 seconds for a host port, inspecting Docker
// again on each attempt instead of relying on dockertest's startup snapshot.
func WaitForPublishedPort(ctx context.Context, inspector ContainerInspector, containerID, portID string) (string, error) {
	port, err := network.ParsePort(portID)
	if err != nil {
		return "", fmt.Errorf("invalid container port %q: %w", portID, err)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	state := "unknown"
	var bindings []network.PortBinding
	failure := func(err error) error {
		return fmt.Errorf("container %s did not publish %s (state=%s, bindings=%v): %w", containerID, portID, state, bindings, err)
	}
	for {
		result, err := inspector.ContainerInspect(ctx, containerID, mobyclient.ContainerInspectOptions{})
		if err != nil {
			return "", failure(err)
		}
		container := result.Container
		if container.NetworkSettings != nil {
			bindings = container.NetworkSettings.Ports[port]
		}
		if container.State != nil {
			state = string(container.State.Status)
			if !container.State.Running && !container.State.Restarting {
				return "", failure(fmt.Errorf("container stopped: exit=%d, error=%s", container.State.ExitCode, container.State.Error))
			}
		}
		for _, binding := range bindings {
			if number, err := strconv.Atoi(binding.HostPort); err == nil && number > 0 && number <= 65535 {
				return binding.HostPort, nil
			}
		}
		select {
		case <-ctx.Done():
			return "", failure(ctx.Err())
		case <-ticker.C:
		}
	}
}
