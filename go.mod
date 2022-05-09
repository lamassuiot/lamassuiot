module github.com/lamassuiot/lamassuiot

go 1.16

replace github.com/lamassuiot/lamassu-aws-connector => /home/ikerlan/lamassu/lamassu-aws-2/aws-connector

require (
	cloud.google.com/go/kms v1.4.0 // indirect
	cloud.google.com/go/monitoring v1.5.0 // indirect
	github.com/cloudevents/sdk-go/v2 v2.6.0
	github.com/coreos/go-oidc/v3 v3.1.0 // indirect
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/getkin/kin-openapi v0.88.0
	github.com/globalsign/pemfile v1.0.0
	github.com/go-kit/kit v0.12.0
	github.com/go-kit/log v0.2.0
	github.com/go-openapi/runtime v0.21.0
	github.com/go-playground/validator/v10 v10.10.0
	github.com/golang-migrate/migrate/v4 v4.15.2
	github.com/google/uuid v1.3.0
	github.com/gorilla/mux v1.8.0
	github.com/hashicorp/consul/api v1.10.1
	github.com/hashicorp/go-cleanhttp v0.5.2
	github.com/hashicorp/vault v1.7.3
	github.com/hashicorp/vault/api v1.1.1
	github.com/hashicorp/vault/sdk v0.2.1
	github.com/jakehl/goid v1.1.0
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/lamassuiot/lamassu-aws-connector v0.0.0-00010101000000-000000000000
	github.com/lib/pq v1.10.0
	github.com/moby/sys/mount v0.3.2 // indirect
	github.com/opentracing/opentracing-go v1.2.0
	github.com/prometheus/client_golang v1.11.0
	github.com/streadway/amqp v1.0.0
	github.com/uber/jaeger-client-go v2.25.0+incompatible
	go.mozilla.org/pkcs7 v0.0.0-20200128120323-432b2356ecb1

)
