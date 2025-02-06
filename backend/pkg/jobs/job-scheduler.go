package jobs

import (
	"github.com/robfig/cron/v3"
	"github.com/sirupsen/logrus"
)

type JobScheduler struct {
	scheduler *cron.Cron
	logger    *logrus.Entry
}

func NewJobScheduler(enableSecondLvlCron bool, logger *logrus.Entry) *JobScheduler {
	cronInstance := cron.New()
	if enableSecondLvlCron {
		logger.Warn("periodic monitoring system contains 'second level' scheduling. This may cause performance issues in production scenarios")
		cronInstance = cron.New(cron.WithSeconds())
	}

	return &JobScheduler{
		scheduler: cronInstance,
		logger:    logger,
	}
}

func (js *JobScheduler) Start() {
	jobs := js.scheduler.Entries()
	if len(jobs) > 0 {
		js.scheduler.Start()
	} else {
		js.logger.Warn("no scheduled jobs found")
	}
}

func (js *JobScheduler) AddJob(interval string, fn func()) cron.EntryID {
	jobId, err := js.scheduler.AddJob(interval, cron.FuncJob(fn))
	if err != nil {
		js.logger.Errorf("could not add scheduled run for job: %v", err)
	}

	return jobId
}

func (js *JobScheduler) Schedule(schedule cron.Schedule, fn func()) cron.EntryID {
	jobId := js.scheduler.Schedule(schedule, cron.FuncJob(fn))
	return jobId
}

func (js *JobScheduler) RemoveJob(id cron.EntryID) {
	js.scheduler.Remove(id)
}

func (js *JobScheduler) Stop() {
	<-js.scheduler.Stop().Done()
}
