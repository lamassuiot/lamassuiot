package jobs

import (
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/sirupsen/logrus"
)

type AlertsEventCleanup struct {
	logger           *logrus.Entry
	storedEventsRepo storage.StoredEventsRepository
}

func NewAlertsEventCleanup(storedEventsRepo storage.StoredEventsRepository, logger *logrus.Entry) *AlertsEventCleanup {
	return &AlertsEventCleanup{
		storedEventsRepo: storedEventsRepo,
		logger:           logger,
	}
}

func (j *AlertsEventCleanup) Run() {
	ctx := helpers.InitContext()
	lFunc := helpers.ConfigureLogger(ctx, j.logger)

	lFunc.Info("starting periodic cleanup of expired stored events")

	deleted, err := j.storedEventsRepo.DeleteExpired(ctx)
	if err != nil {
		lFunc.Errorf("error while deleting expired stored events: %s", err)
		return
	}

	lFunc.Infof("deleted %d expired stored events", deleted)
}
