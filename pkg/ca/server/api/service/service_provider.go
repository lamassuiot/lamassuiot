package service

import (
	"context"
	"fmt"
	"time"

	"github.com/lamassuiot/lamassuiot/pkg/ca/common/api"
	"github.com/lamassuiot/lamassuiot/pkg/utils/common"
	"github.com/lamassuiot/lamassuiot/pkg/utils/server"
	"github.com/robfig/cron/v3"
	log "github.com/sirupsen/logrus"
)

type ServiceProvider interface {
	Service
	ScanAboutToExpireCertificates(ctx context.Context, input *api.ScanAboutToExpireCertificatesInput) (*api.ScanAboutToExpireCertificatesOutput, error)
	ScanExpiredAndOutOfSyncCertificates(ctx context.Context, input *api.ScanExpiredAndOutOfSyncCertificatesInput) (*api.ScanExpiredAndOutOfSyncCertificatesOutput, error)
}

type ServiceProviderContext struct {
	Service
	cronInstance *cron.Cron
}

func NewServiceProvider(serviceInstance Service, amqpPublisher *chan server.AmqpPublishMessage) ServiceProvider {
	serviceInstance = NewAMQPMiddleware(*amqpPublisher)(serviceInstance)
	serviceInstance = NewInputValudationMiddleware()(serviceInstance)
	// serviceInstance = LoggingMiddleware(s)(serviceInstance)

	cronInstance := cron.New()

	svc := ServiceProviderContext{
		Service:      serviceInstance,
		cronInstance: cronInstance,
	}

	_, err := serviceInstance.GetCAByName(context.Background(), &api.GetCAByNameInput{
		CAType: api.CATypeDMSEnroller,
		CAName: "LAMASSU-DMS-MANAGER",
	})

	if err != nil {
		log.Warn("failed to get LAMASSU-DMS-MANAGER: ", err)
		log.Warn("generating LAMASSU-DMS-MANAGER CA")
		serviceInstance.CreateCA(context.Background(), &api.CreateCAInput{
			CAType: api.CATypeDMSEnroller,
			Subject: api.Subject{
				CommonName:   "LAMASSU-DMS-MANAGER",
				Organization: "lamassu",
			},
			KeyMetadata: api.KeyMetadata{
				KeyType: api.RSA,
				KeyBits: 4096,
			},
			CADuration:       time.Hour * 24 * 365 * 5,
			IssuanceDuration: time.Hour * 24 * 365 * 3,
		})
	}

	cronInstance.AddFunc("0 * * * *", func() { // runs daily
		log.Info("msg", "Starting scan")
		output1, err := svc.ScanAboutToExpireCertificates(context.Background(), &api.ScanAboutToExpireCertificatesInput{})
		if err != nil {
			log.Error("Error while perfoming AboutToExpire scan: ", err)
		} else {
			log.Info(fmt.Sprintf("Total AboutToExpire scanned certificates: %d", output1.AboutToExpiredTotal))
		}

		output2, err := svc.ScanExpiredAndOutOfSyncCertificates(context.Background(), &api.ScanExpiredAndOutOfSyncCertificatesInput{})
		if err != nil {
			log.Error("Error while perfoming Expired scan: ", err)
		} else {
			log.Info(fmt.Sprintf("Total Expired scanned certificates: %d", output2.TotalExpired))
		}
	})

	return svc
}

func (s ServiceProviderContext) ScanAboutToExpireCertificates(ctx context.Context, input *api.ScanAboutToExpireCertificatesInput) (*api.ScanAboutToExpireCertificatesOutput, error) {
	limit := 100
	i := 0
	total := 0

	for {
		getCertificatesOutput, err := s.GetCertificatesAboutToExpire(ctx, &api.GetCertificatesAboutToExpireInput{
			QueryParameters: common.QueryParameters{
				Pagination: common.PaginationOptions{
					Limit:  limit,
					Offset: i * limit,
				},
			},
		})
		if err != nil {
			return nil, err
		}

		total = getCertificatesOutput.TotalCertificates

		if len(getCertificatesOutput.Certificates) == 0 {
			break
		}

		i++

		for _, cert := range getCertificatesOutput.Certificates {
			s.UpdateCertificateStatus(ctx, &api.UpdateCertificateStatusInput{
				CAType:                  cert.CAType,
				CAName:                  cert.CAName,
				CertificateSerialNumber: cert.SerialNumber,
				Status:                  api.StatusAboutToExpire,
			})
		}
	}

	return &api.ScanAboutToExpireCertificatesOutput{
		AboutToExpiredTotal: total,
	}, nil
}

func (s ServiceProviderContext) ScanExpiredAndOutOfSyncCertificates(ctx context.Context, input *api.ScanExpiredAndOutOfSyncCertificatesInput) (*api.ScanExpiredAndOutOfSyncCertificatesOutput, error) {
	limit := 100
	i := 0
	total := 0

	for {
		getCertificatesOutput, err := s.GetExpiredAndOutOfSyncCertificates(ctx, &api.GetExpiredAndOutOfSyncCertificatesInput{
			QueryParameters: common.QueryParameters{
				Pagination: common.PaginationOptions{
					Limit:  limit,
					Offset: i * limit,
				},
			},
		})

		total = getCertificatesOutput.TotalCertificates

		if err != nil {
			return nil, err
		}
		if len(getCertificatesOutput.Certificates) == 0 {
			break
		}

		i++

		for _, cert := range getCertificatesOutput.Certificates {
			s.UpdateCertificateStatus(ctx, &api.UpdateCertificateStatusInput{
				CAType:                  cert.CAType,
				CAName:                  cert.CAName,
				CertificateSerialNumber: cert.SerialNumber,
				Status:                  api.StatusExpired,
			})
		}
	}

	return &api.ScanExpiredAndOutOfSyncCertificatesOutput{
		TotalExpired: total,
	}, nil
}
