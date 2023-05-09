package discovery

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/hashicorp/consul/api"
	uuid "github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

type ServiceDiscovery struct {
	consulClient *api.Client
	registration *api.AgentServiceRegistration
}

func NewServiceDiscovery(consulProtocol string, consulHost string, consulPort string, CA string, insecureVerify bool) (*ServiceDiscovery, error) {
	consulConfig := api.DefaultConfig()
	consulConfig.Address = consulProtocol + "://" + consulHost + ":" + consulPort
	tlsConf := &api.TLSConfig{}
	if insecureVerify {
		tlsConf.InsecureSkipVerify = true
	} else {
		tlsConf.CAFile = CA
	}
	consulConfig.TLSConfig = *tlsConf
	consulClient, err := api.NewClient(consulConfig)
	if err != nil {
		return nil, err
	}

	return &ServiceDiscovery{
		consulClient: consulClient,
	}, nil
}

func (sd *ServiceDiscovery) CheckHealth() (bool, []api.Node, error) {
	nodes, _, err := sd.consulClient.Catalog().Nodes(&api.QueryOptions{})
	if err != nil {
		return false, []api.Node{}, err
	}

	healthyNodes := []api.Node{}
	for _, node := range nodes {
		healthChecks, _, err := sd.consulClient.Health().Node(node.Node, &api.QueryOptions{})
		for _, healthCheck := range healthChecks {
			if healthCheck.CheckID == "serfHealth" {
				if err != nil || healthCheck.Status != "passing" {
					log.Debug(fmt.Sprintf("Consul node %s not healthy", node.Node))
				} else {
					healthyNodes = append(healthyNodes, *node)
				}

			}
		}
	}

	log.Info(fmt.Sprintf("Consul healthy nodes: %d/%d", len(healthyNodes), len(nodes)))

	if len(healthyNodes) == 0 {
		return false, []api.Node{}, nil
	}

	return true, healthyNodes, nil
}

func (sd *ServiceDiscovery) Register(advProtocol string, advPort string, tags []string, name string, persistenceDir string) (string, error) {

	cmd := exec.Command("hostname", "-i")
	stdout, err := cmd.Output()
	if err != nil {
		return "", err
	}
	strStdout := strings.TrimSuffix(string(stdout), "\n")

	check := api.AgentServiceCheck{
		HTTP:          advProtocol + "://" + strStdout + ":" + advPort + "/v1/health",
		Interval:      "10s",
		Timeout:       "1s",
		TLSSkipVerify: true,
		Notes:         "Basic health checks",
	}

	meta := map[string]string{"connector-type": tags[0], "name": name, "protocol": advProtocol}

	var svcId string
	if _, err := os.Stat(persistenceDir + "/identifier"); errors.Is(err, os.ErrNotExist) {
		svcId = uuid.NewV4().String()
		os.WriteFile(persistenceDir+"/identifier", []byte(svcId), 0640)
	} else {
		data, err := os.ReadFile(persistenceDir + "/identifier")
		if err != nil {
			return "", nil
		}
		svcId = string(data)
		isValidUUID := func(uuid string) bool {
			r := regexp.MustCompile("^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$")
			return r.MatchString(uuid)
		}
		if !isValidUUID(svcId) {
			return "", errors.New("invalid uuidv4 string")
		}
	}
	port, _ := strconv.Atoi(advPort)
	asr := api.AgentServiceRegistration{
		ID:      svcId,
		Name:    "cloud-connector",
		Address: strStdout,
		Port:    port,
		Tags:    tags,
		Meta:    meta,
		Check:   &check,
	}

	sd.registration = &asr
	return svcId, sd.consulClient.Agent().ServiceRegister(sd.registration)
}
