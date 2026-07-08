package subsystem

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	rabbitmq_test "github.com/lamassuiot/lamassuiot/engines/eventbus/amqp/v3/test"
	"github.com/lamassuiot/lamassuiot/shared/subsystems/v3/pkg/test/subsystems"
)

func Register() {
	subsystems.RegisterSubsystemBuilder(subsystems.RabbitMQ, &RabbitMQSubsystem{})
}

type RabbitMQSubsystem struct {
}

func (p *RabbitMQSubsystem) Run(exposeAsStandardPort bool) (*subsystems.SubsystemBackend, error) {
	cleanup, conf, adminPort, err := rabbitmq_test.RunRabbitMQDocker(exposeAsStandardPort)
	if err != nil {
		return nil, err
	}

	eventBusConfig, err := config.EncodeStruct(conf)
	if err != nil {
		return nil, err
	}

	return &subsystems.SubsystemBackend{
		Config: config.EventBusEngine{
			LogLevel: config.Trace,
			Enabled:  true,
			Provider: config.Amqp,
			Config:   eventBusConfig,
		},
		Extra: &map[string]interface{}{
			"adminPort": adminPort,
		},
		AfterSuite: func() { cleanup() },
		BeforeEach: func() error {
			return purgeAndDrainQueues(adminPort)
		},
	}, nil

}
func purgeAndDrainQueues(adminPort int) error {
	type named struct {
		Name  string `json:"name"`
		Vhost string `json:"vhost"`
	}

	baseURL := fmt.Sprintf("http://user:user@127.0.0.1:%d", adminPort)
	cli := &http.Client{Timeout: 5 * time.Second}

	doDelete := func(path string) {
		req, _ := http.NewRequest(http.MethodDelete, baseURL+path, nil)
		cli.Do(req) //nolint:errcheck // best-effort
	}

	getJSON := func(path string, dst interface{}) error {
		resp, err := cli.Get(baseURL + path)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		return json.NewDecoder(resp.Body).Decode(dst)
	}

	// Close all connections so the broker requeues any unacked messages.
	var connections []named
	if err := getJSON("/api/connections", &connections); err != nil {
		return nil // management API not ready yet
	}
	for _, c := range connections {
		doDelete("/api/connections/" + url.PathEscape(c.Name))
	}

	// Brief pause for the broker to process the connection close and requeue
	if len(connections) > 0 {
		time.Sleep(300 * time.Millisecond)
	}

	// Purge every queue (now all messages are in ready state).
	var queues []named
	if err := getJSON("/api/queues", &queues); err != nil {
		return nil
	}
	for _, q := range queues {
		doDelete("/api/queues/" + url.PathEscape(q.Vhost) + "/" + url.PathEscape(q.Name) + "/contents")
	}

	return nil
}
