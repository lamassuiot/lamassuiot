package azure

import (
	"context"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/log/level"
)

type AzureService interface {
	RegisterCA(ctx context.Context, caName string, caSerialNumber string, caCertificate string) error
	AttachAccessPolicy(ctx context.Context) error
	GetConfiguration(ctx context.Context) interface{}
}

type AzureConnectorSettings struct {
	logger log.Logger
	IP     string
	Port   string
}

func NewAzureConnectorClient(ip string, port string, logger log.Logger) AzureService {
	return &AzureConnectorSettings{
		logger: logger,
		IP:     ip,
		Port:   port,
	}
}

func (s *AzureConnectorSettings) RegisterCA(ctx context.Context, caName string, caSerialNumber string, caCertificate string) error {
	level.Info(s.logger).Log("msg", "Resgitering CA to Azure")
	return nil
}

func (s *AzureConnectorSettings) AttachAccessPolicy(ctx context.Context) error {
	return nil
}

func (s *AzureConnectorSettings) GetConfiguration(ctx context.Context) interface{} {
	return ""
}
