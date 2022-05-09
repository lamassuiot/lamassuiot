package consul

import (
	"strconv"

	"math/rand"

	"github.com/lamassuiot/lamassuiot/pkg/device-manager/server/discovery"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	consulsd "github.com/go-kit/kit/sd/consul"
	"github.com/hashicorp/consul/api"
)

type ServiceDiscovery struct {
	client       consulsd.Client
	logger       log.Logger
	registration *api.AgentServiceRegistration
}

func NewServiceDiscovery(consulProtocol string, consulHost string, consulPort string, CA string, logger log.Logger) (discovery.Service, error) {
	consulConfig := api.DefaultConfig()
	consulConfig.Address = consulProtocol + "://" + consulHost + ":" + consulPort
	tlsConf := &api.TLSConfig{CAFile: CA}
	consulConfig.TLSConfig = *tlsConf
	consulClient, err := api.NewClient(consulConfig)
	if err != nil {
		level.Debug(logger).Log("err", err, "msg", "Could not start Consul API Client")
		return nil, err
	}
	client := consulsd.NewClient(consulClient)
	return &ServiceDiscovery{client: client, logger: logger}, nil
}

func (sd *ServiceDiscovery) Register(advProtocol string, advHost string, advPort string) error {
	check := api.AgentServiceCheck{
		HTTP:          advProtocol + "://" + advHost + ":" + advPort + "/v1/health",
		Interval:      "10s",
		Timeout:       "1s",
		TLSSkipVerify: true,
		Notes:         "Basic health checks",
	}

	port, _ := strconv.Atoi(advPort)
	num := rand.Intn(100)
	asr := api.AgentServiceRegistration{
		ID:      "device" + strconv.Itoa(num),
		Name:    "device",
		Address: advHost,
		Port:    port,
		Tags:    []string{"device", "device"},
		Check:   &check,
	}
	sd.registration = &asr
	return sd.client.Register(sd.registration)
}

func (sd *ServiceDiscovery) Deregister() error {
	return sd.client.Deregister(sd.registration)
}
