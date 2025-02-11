package jobs

import (
	"testing"

	"github.com/sirupsen/logrus"
)

type mockJob struct{}

func (mj *mockJob) Run() {
	// do nothing
}

func TestNewJobSchedulerWithoutJob(t *testing.T) {
	logger := logrus.New().WithField("test", "test")

	js := NewJobScheduler(logger, "0 0 * * *", nil)
	js.Start()
	if len(js.scheduler.Entries()) != 0 {
		t.Error("expected no jobs to be scheduled")
	}

	if !js.NextRun().IsZero() {
		t.Error("expected NextRun to be zero")
	}

	js.Stop()

	t.Cleanup(func() {
		js.Stop()
	})
}

func TestNewJobSchedulerDisabled(t *testing.T) {
	logger := logrus.New().WithField("test", "test")
	job := &mockJob{}

	js := NewJobScheduler(logger, "0 0 * * *", job)
	js.Start()

	if len(js.scheduler.Entries()) != 0 {
		t.Error("expected no jobs to be scheduled")
	}

	if !js.NextRun().IsZero() {
		t.Error("expected NextRun to be zero")
	}

	js.Stop()

	t.Cleanup(func() {
		js.Stop()
	})
}

func TestNewJobScheduler(t *testing.T) {
	logger := logrus.New().WithField("test", "test")
	job := &mockJob{}

	js := NewJobScheduler(logger, "0 0 * * *", job)
	js.Start()

	if js.logger != logger {
		t.Errorf("unexpected logger, got: %v, want: %v", js.logger, logger)
	}

	if js.job != job {
		t.Errorf("unexpected job, got: %v, want: %v", js.job, job)
	}

	if js.jobId == 0 {
		t.Error("expected jobId to be non-zero")
	}
}

func TestJobSchedulerStart(t *testing.T) {
	logger := logrus.New().WithField("test", "test")
	job := &mockJob{}

	js := NewJobScheduler(logger, "0 0 * * *", job)
	js.Start()

	t.Cleanup(func() {
		js.Stop()
	})

	if js.NextRun().IsZero() {
		t.Error("expected cronInstance to be running")
	}
}

func TestJobSchedulerNextRun(t *testing.T) {
	logger := logrus.New().WithField("test", "test")
	job := &mockJob{}

	js := NewJobScheduler(logger, "0 0 * * *", job)
	js.Start()
	t.Cleanup(func() {
		js.Stop()
	})

	nextRun := js.NextRun()

	if nextRun.IsZero() {
		t.Error("expected nextRun to be non-zero")
	}
}

func TestJobSchedulerInSeconds(t *testing.T) {
	logger := logrus.New().WithField("test", "test")
	job := &mockJob{}

	js := NewJobScheduler(logger, "0 0 * * *", job)
	js.Start()
	t.Cleanup(func() {
		js.Stop()
	})

	nextRun := js.NextRun()

	if nextRun.IsZero() {
		t.Error("expected nextRun to be non-zero")
	}
}

func TestJobSchedulerStop(t *testing.T) {
	logger := logrus.New().WithField("test", "test")
	job := &mockJob{}

	js := NewJobScheduler(logger, "0 0 * * *", job)
	js.Start()
	t.Cleanup(func() {
		js.Stop()
	})

	if !js.NextRun().IsZero() {
		t.Error("expected cronInstance to be stopped")
	}
}
