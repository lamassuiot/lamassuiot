package jobs

import (
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
	f, err := GetSchedulerPeriod(frequency)
	if err != nil {
		f = time.Duration(30 * time.Minute)
		logger.Warnf("could not parse frequency. defaulting to %s: %v", err, f)
	}

	if f < time.Minute {
		logger.Warn("periodic monitoring system contains 'sub-minute' scheduling. This may cause performance issues in production scenarios")
		scheduler = cron.New(cron.WithSeconds())
	}

	cds := cron.ConstantDelaySchedule{
		Delay: f,
	}

	if job != nil {
		jobId = scheduler.Schedule(cds, job)
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

func GetSchedulerPeriod(frequency string) (time.Duration, error) {
	// First parse as regular duration
	dur, err := time.ParseDuration(frequency)
	if err == nil {
		return dur, nil
	}

	// Fallback to parse as cron expression
	schedule, err := cron.ParseStandard(frequency)
	if err != nil {
		return 0, err
	}

	now := time.Now()
	nextFire := schedule.Next(now)
	period := nextFire.Sub(now)
	return period, nil
}
