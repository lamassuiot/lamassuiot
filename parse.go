package main

import (
	"errors"
	"log"
	"os"

	"gopkg.in/yaml.v3"
)

func main() {

	f, err := os.ReadFile("/home/lamassu/lamassu-compose/docker-compose.yml")
	if err != nil {
		log.Fatal(err)
	}
	var dockerYaml map[string]interface{}
	var services map[string]interface{}
	var ca map[string]interface{}
	err = yaml.Unmarshal(f, &dockerYaml)

	if err != nil {
		log.Fatal(err)
	}
	//fmt.Println(dockerYaml)
	service, ok := dockerYaml["services"]
	if !ok {
		log.Fatal(errors.New("services"))
	}
	services = service.(map[string]interface{})
	lamassuca, ok := services["lamassu-ca"]
	if !ok {
		log.Fatal(errors.New("lamassu-ca"))
	}
	ca = lamassuca.(map[string]interface{})
	caenv, ok := ca["environment"]
	if !ok {
		log.Fatal(errors.New("environment"))
	}
	env := caenv.(map[string]interface{})
	lamassu_ca := map[string]interface{}{
		"build":          ca["build"],
		"container_name": ca["container_name"],
		"environment": map[string]interface{}{
			"DEBUG_MODE":                           env["DEBUG_MODE"],
			"PORT":                                 env["PORT"],
			"PROTOCOL":                             env["PROTOCOL"],
			"MUTUAL_TLS_ENABLED":                   env["MUTUAL_TLS_ENABLED"],
			"MUTUAL_TLS_CLIENT_CA":                 env["MUTUAL_TLS_CLIENT_CA"],
			"OCSP_URL":                             env["OCSP_URL"],
			"POSTGRES_HOSTNAME":                    env["POSTGRES_HOSTNAME"],
			"POSTGRES_PORT":                        env["POSTGRES_PORT"],
			"POSTGRES_CA_DB":                       env["POSTGRES_CA_DB"],
			"POSTGRES_USER":                        env["POSTGRES_USER"],
			"POSTGRES_PASSWORD":                    env["POSTGRES_PASSWORD"],
			"POSTGRES_MIGRATIONS_FILE_PATH":        env["POSTGRES_MIGRATIONS_FILE_PATH"],
			"CERT_FILE":                            env["CERT_FILE"],
			"KEY_FILE":                             env["KEY_FILE"],
			"JAEGER_SERVICE_NAME":                  env["JAEGER_SERVICE_NAME"],
			"JAEGER_AGENT_HOST":                    env["JAEGER_AGENT_HOST"],
			"JAEGER_AGENT_PORT":                    env["JAEGER_AGENT_PORT"],
			"JAEGER_SAMPLER_TYPE":                  env["JAEGER_SAMPLER_TYPE"],
			"JAEGER_SAMPLER_PARAM":                 env["JAEGER_SAMPLER_PARAM"],
			"JAEGER_REPORTER_LOG_SPANS":            env["JAEGER_REPORTER_LOG_SPANS"],
			"AMQP_IP":                              env["AMQP_IP"],
			"AMQP_PORT":                            env["AMQP_PORT"],
			"AMQP_SERVER_CA_CERT_FILE":             env["AMQP_SERVER_CA_CERT_FILE"],
			"OPENAPI_ENABLE_SECURITY_SCHEMA":       env["OPENAPI_ENABLE_SECURITY_SCHEMA"],
			"OPENAPI_SECURITY_OIDC_WELL_KNOWN_URL": env["OPENAPI_SECURITY_OIDC_WELL_KNOWN_URL"],
			"PKCS11_PROXY_TLS_PSK_FILE":            "/home/ikerlan/pkcs11-proxy/test.psk",
			"PKCS11_PROXY_SOCKET":                  "tls://127.0.0.1:5657",
			"PKCS11_DRIVER":                        "softhsm",
			"PKCS11_LABEL":                         "lamassu",
			"PKCS11_PIN":                           "1234",
		},
		"volumes": ca["volumes"],
		"restart": ca["restart"],
	}
	newService := map[string]interface{}{
		"api-gateway":            services["api-gateway"],
		"lamassu-db":             services["lamassu-db"],
		"opa-server":             services["opa-server"],
		"jaeger":                 services["jaeger"],
		"ui":                     services["ui"],
		"vault":                  services["vault"],
		"auth":                   services["auth"],
		"lamassu-ca":             lamassu_ca,
		"lamassu-dms-enroller":   services["lamassu-dms-enroller"],
		"lamassu-device-manager": services["lamassu-device-manager"],
		"ocsp":                   services["ocsp"],
		"rabbitmq":               services["rabbitmq"],
		"cloud-proxy":            services["cloud-proxy"],
	}
	newdockerYml := map[string]interface{}{
		"version":  dockerYaml["version"],
		"networks": dockerYaml["networks"],
		"volumes":  dockerYaml["volumes"],
		"services": newService,
	}
	out, err := yaml.Marshal(newdockerYml)
	if err != nil {
		log.Fatal(err)
	}
	err = os.WriteFile("/home/lamassu/lamassu-compose/docker-compose2.yml", out, 0755)
	if err != nil {
		log.Fatal(err)
	}
}
