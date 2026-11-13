package dockerrunner

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	mobyclient "github.com/moby/moby/client"
)

type inspectFunc func(context.Context, string, mobyclient.ContainerInspectOptions) (mobyclient.ContainerInspectResult, error)

func (f inspectFunc) ContainerInspect(ctx context.Context, id string, options mobyclient.ContainerInspectOptions) (mobyclient.ContainerInspectResult, error) {
	return f(ctx, id, options)
}

func TestWaitForPublishedPortRefreshesBindings(t *testing.T) {
	calls := 0
	inspector := inspectFunc(func(_ context.Context, id string, _ mobyclient.ContainerInspectOptions) (mobyclient.ContainerInspectResult, error) {
		if id != "oracle-test" {
			t.Fatalf("inspected unexpected container %q", id)
		}
		calls++
		ports := network.PortMap{
			network.MustParsePort("5500/tcp"): {{HostPort: "49151"}},
			network.MustParsePort("1521/tcp"): {{HostPort: ""}},
		}
		if calls > 1 {
			ports[network.MustParsePort("1521/tcp")] = []network.PortBinding{{HostPort: ""}, {HostPort: "49152"}}
		}
		return mobyclient.ContainerInspectResult{Container: container.InspectResponse{
			State:           &container.State{Status: "running", Running: true},
			NetworkSettings: &container.NetworkSettings{Ports: ports},
		}}, nil
	})
	port, err := WaitForPublishedPort(t.Context(), inspector, "oracle-test", "1521/tcp")
	if err != nil || port != "49152" || calls != 2 {
		t.Fatalf("port=%q calls=%d error=%v", port, calls, err)
	}
}

func TestWaitForPublishedPortReportsStoppedContainer(t *testing.T) {
	inspector := inspectFunc(func(context.Context, string, mobyclient.ContainerInspectOptions) (mobyclient.ContainerInspectResult, error) {
		return mobyclient.ContainerInspectResult{Container: container.InspectResponse{
			State: &container.State{Status: "exited", ExitCode: 1, Error: "startup failed"},
		}}, nil
	})
	_, err := WaitForPublishedPort(t.Context(), inspector, "oracle-test", "1521/tcp")
	if err == nil || !strings.Contains(err.Error(), "state=exited") || !strings.Contains(err.Error(), "exit=1, error=startup failed") {
		t.Fatalf("expected container failure details, got %v", err)
	}
}

func TestWaitForPublishedPortHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	inspector := inspectFunc(func(context.Context, string, mobyclient.ContainerInspectOptions) (mobyclient.ContainerInspectResult, error) {
		cancel()
		return mobyclient.ContainerInspectResult{Container: container.InspectResponse{
			State: &container.State{Status: "running", Running: true},
		}}, nil
	})
	_, err := WaitForPublishedPort(ctx, inspector, "oracle-test", "1521/tcp")
	if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "oracle-test did not publish 1521/tcp (state=running") {
		t.Fatalf("expected cancellation and container diagnostics, got %v", err)
	}
}

func TestWaitForPublishedPortReportsInspectError(t *testing.T) {
	wantErr := errors.New("Docker unavailable")
	inspector := inspectFunc(func(context.Context, string, mobyclient.ContainerInspectOptions) (mobyclient.ContainerInspectResult, error) {
		return mobyclient.ContainerInspectResult{}, wantErr
	})
	_, err := WaitForPublishedPort(t.Context(), inspector, "oracle-test", "1521/tcp")
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected inspect error, got %v", err)
	}
}
