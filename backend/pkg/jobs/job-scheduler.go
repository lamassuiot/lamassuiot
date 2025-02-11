package jobs

import (
	"strings"
	"time"

	"github.com/robfig/cron/v3"
	"github.com/sirupsen/logrus"
)

type JobScheduler struct {
	scheduler *cron.Cron
	logger    *logrus.Entry
	job       cron.Job
	jobId     cron.EntryID
}

func NewJobScheduler(logger *logrus.Entry, frequency string, job cron.Job) *JobScheduler {
	scheduler := cron.New()

	var err error
	var jobId cron.EntryID

	logger.Infof("enabling periodic monitoring with cron expression: '%s'", frequency)
	if strings.Count(frequency, " ") == 5 {
		logger.Warn("periodic monitoring system contains 'second level' scheduling. This may cause performance issues in production scenarios")
		scheduler = cron.New(cron.WithSeconds())
	}

	if job != nil {
		jobId, err = scheduler.AddJob(frequency, job)
		if err != nil {
			logger.Errorf("could not add scheduled run for job: %v", err)
		}
	}

	return &JobScheduler{
		scheduler: scheduler,
		logger:    logger,
		job:       job,
		jobId:     jobId,
	}
}

func (js *JobScheduler) Start() {
	js.scheduler.Start()
}

func (js *JobScheduler) NextRun() time.Time {
	return js.scheduler.Entry(js.jobId).Next
}

func (js *JobScheduler) Stop() {
	js.scheduler.Remove(js.jobId)
	<-js.scheduler.Stop().Done()
}
