package docker

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	pconfig "github.com/lamassuiot/lamassuiot/engines/crypto/pkcs11/v3/config"
	dockerrunner "github.com/lamassuiot/lamassuiot/shared/subsystems/v3/pkg/test/dockerrunner"
	"github.com/ory/dockertest/v4"
)

func RunNetHsmV2Docker(exposeAsStandardPort bool, pkcs11ProxyPath string) (func() error, func() error, pconfig.PKCS11Config, error) {
	label := "LocalHSM"

	admin := "abcdefghijklm"
	unlock := "a0b1c2d3e4f5"
	operator := "0123456789"

	containerCleanup, container, _, err := dockerrunner.RunDocker("nitrokey/nethsm",
		dockertest.WithTag("testing"),
		dockertest.WithLabels(map[string]string{
			"group": "lamassuiot-monolithic",
		}),
	)
	if err != nil {
		return nil, nil, pconfig.PKCS11Config{}, err
	}

	p, err := strconv.Atoi(container.GetPort("8443/tcp"))
	if err != nil {
		containerCleanup()
		return nil, nil, pconfig.PKCS11Config{}, fmt.Errorf("could not parse container port: %w", err)
	}

	container.Exec(context.Background(), []string{"sh", "-c", "apk add --no-cache opensc"})

	cli := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	hsmBaseURL := fmt.Sprintf("https://localhost:%d/api/v1", p)

	//give 5 seconds for the HSM to start up
	time.Sleep(5 * time.Second)

	body := fmt.Sprintf(`{"unlockPassphrase": "%s","adminPassphrase": "%s","systemTime": "%s"}`, unlock, admin, "2026-01-01T00:00:00Z")
	resp, err := cli.Post(fmt.Sprintf("%s/provision", hsmBaseURL), "application/json", strings.NewReader(body))
	if err != nil {
		containerCleanup()
		return nil, nil, pconfig.PKCS11Config{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 204 {
		containerCleanup()
		return nil, nil, pconfig.PKCS11Config{}, fmt.Errorf("failed to provision NetHSM: %s", resp.Status)
	}

	body = fmt.Sprintf(`{"realName": "Jon Doe","role": "Operator","passphrase": "%s"}`, operator)
	req, _ := http.NewRequest("POST", fmt.Sprintf("%s/users", hsmBaseURL), strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("admin", admin)
	resp, err = cli.Do(req)
	if err != nil {
		containerCleanup()
		return nil, nil, pconfig.PKCS11Config{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 {
		containerCleanup()
		return nil, nil, pconfig.PKCS11Config{}, fmt.Errorf("failed to create operator user: %s", resp.Status)
	}

	operatorID := ""
	// Extract the operator ID from the response body
	type userResponse struct {
		ID string `json:"id"`
	}
	var ur userResponse
	err = json.NewDecoder(resp.Body).Decode(&ur)
	if err != nil {
		containerCleanup()
		return nil, nil, pconfig.PKCS11Config{}, fmt.Errorf("failed to decode operator user response: %v", err)
	}

	operatorID = ur.ID

	pkcs11ClientConfig := fmt.Sprintf(`
log_level: Debug
syslog_socket: /var/nethsm/log
syslog_facility: "user"
log_file: /tmp/p11nethsm.log

slots:
  - label: LocalHSM                        # Name your NetHSM however you want
    description: Local HSM (docker)        # Optional description

    operator:
      username: "%s"
      password: "%s"
    administrator:
      username: "admin"
      password: "%s"
    instances:
      - url: "https://localhost:%d/api/v1"   # URL to reach the server
        max_idle_connections: 10
        danger_insecure_cert: true
    certificate_format: PEM
    retries:
      count: 3
      delay_seconds: 1
    tcp_keepalive:
      time_seconds: 600
      interval_seconds: 60
      retries: 3
    connections_max_idle_duration: 1800
    timeout_seconds: 10
`, operatorID, operator, admin, p)

	if err := os.WriteFile("/tmp/nethsm_cli_conf.yaml", []byte(pkcs11ClientConfig), 0644); err != nil {
		containerCleanup()
		return nil, nil, pconfig.PKCS11Config{}, fmt.Errorf("failed to write NetHSM client config: %w", err)
	}

	return func() error {
			return netHSMBeforeEachCleanup(cli, hsmBaseURL, admin)
		},
		containerCleanup,
		pconfig.PKCS11Config{
			TokenLabel: label,
			TokenPin:   cconfig.Password(operator),
			ModulePath: pkcs11ProxyPath,
			ModuleExtraOptions: pconfig.PKCS11ModuleExtraOptions{
				Env: map[string]string{
					"P11NETHSM_CONFIG_FILE": "/tmp/nethsm_cli_conf.yaml",
				},
			},
		}, nil
}

func netHSMBeforeEachCleanup(cli *http.Client, hsmBaseURL string, adminPassphrase string) error {
	req, _ := http.NewRequest("GET", fmt.Sprintf("%s/keys", hsmBaseURL), nil)
	req.SetBasicAuth("admin", adminPassphrase)
	resp, err := cli.Do(req)
	if err != nil {
		return fmt.Errorf("failed to list keys: %w", err)
	}
	defer resp.Body.Close()

	var keyItems []struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&keyItems); err != nil {
		return fmt.Errorf("failed to decode key list: %w", err)
	}

	for _, item := range keyItems {
		req, _ := http.NewRequest("DELETE", fmt.Sprintf("%s/keys/%s", hsmBaseURL, item.ID), nil)
		req.SetBasicAuth("admin", adminPassphrase)
		resp, err := cli.Do(req)
		if err != nil {
			return fmt.Errorf("failed to delete key %s: %w", item.ID, err)
		}
		resp.Body.Close()
	}

	return nil
}
