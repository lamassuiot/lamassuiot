package gcloud

import (
	"context"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/log/level"
)

type GcloudService interface {
	RegisterCA(ctx context.Context, caName string, caSerialNumber string, caCertificate string) error
	AttachAccessPolicy(ctx context.Context) error
	GetConfiguration(ctx context.Context) interface{}
}

type GcloudConnectorSettings struct {
	logger log.Logger
	IP     string
	Port   string
}

func NewGcloudConnectorClient(ip string, port string, logger log.Logger) GcloudService {
	return &GcloudConnectorSettings{
		logger: logger,
		IP:     ip,
		Port:   port,
	}
}

func (s *GcloudConnectorSettings) RegisterCA(ctx context.Context, caName string, caSerialNumber string, caCertificate string) error {
	level.Info(s.logger).Log("msg", "Resgitering CA to GCloud")
	return nil
}

func (s *GcloudConnectorSettings) AttachAccessPolicy(ctx context.Context) error {
	return nil
}

func (s *GcloudConnectorSettings) GetConfiguration(ctx context.Context) interface{} {
	return ""
}
