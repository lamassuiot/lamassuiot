package jobs

import (
	"strings"
	"time"

	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/robfig/cron/v3"
	"github.com/sirupsen/logrus"
)

type JobScheduler struct {
	config       config.CryptoMonitoring
	cronInstance *cron.Cron
	logger       *logrus.Entry
	job          cron.Job
	jobId        cron.EntryID
}

func NewJobScheduler(config config.CryptoMonitoring, logger *logrus.Entry, job cron.Job) *JobScheduler {
	cronInstance := cron.New()
	var err error
	var jobId cron.EntryID
	if config.Enabled {
		logger.Infof("enabling periodic monitoring with cron expression: '%s'", config.Frequency)
		if strings.Count(config.Frequency, " ") == 5 {
			logger.Warn("periodic monitoring system contains 'second level' scheduling. This may cause performance issues in production scenarios")
			cronInstance = cron.New(cron.WithSeconds())
		}

		if job != nil {
			jobId, err = cronInstance.AddJob(config.Frequency, job)
			if err != nil {
				logger.Errorf("could not add scheduled run for job: %v", err)
			}
		}

	} else {
		logger.Warn("certificate periodic monitoring is disabled")
	}

	return &JobScheduler{config: config,
		cronInstance: cronInstance,
		logger:       logger,
		job:          job,
		jobId:        jobId}
}

func (js *JobScheduler) Start() {
	jobs := js.cronInstance.Entries()
	if len(jobs) > 0 {
		js.cronInstance.Start()
	} else {
		js.logger.Warn("no scheduled jobs found")
	}
}

func (js *JobScheduler) NextRun() time.Time {
	return js.cronInstance.Entry(js.jobId).Next
}

func (js *JobScheduler) Stop() {
	js.cronInstance.Remove(js.jobId)
	<-js.cronInstance.Stop().Done()

}
