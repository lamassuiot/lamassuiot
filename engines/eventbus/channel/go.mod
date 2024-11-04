module github.com/lamassuiot/lamassuiot/v2/eventbus/channel

go 1.22.1

replace github.com/lamassuiot/lamassuiot/v2/core => ../../../core

require (
	github.com/ThreeDotsLabs/watermill v1.3.5
	github.com/lamassuiot/lamassuiot/v2/core v0.0.0-00010101000000-000000000000
	github.com/sirupsen/logrus v1.9.3
)

require (
	github.com/google/uuid v1.6.0 // indirect
	github.com/lithammer/shortuuid/v3 v3.0.7 // indirect
	github.com/oklog/ulid v1.3.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	golang.org/x/sys v0.24.0 // indirect
)
