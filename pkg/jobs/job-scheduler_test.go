package jobs

import (
	"testing"

	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/sirupsen/logrus"
)

type mockJob struct{}

func (mj *mockJob) Run() {
	// do nothing
}

func TestNewJobSchedulerWithoutJob(t *testing.T) {
	config := config.CryptoMonitoring{
		Enabled:   true,
		Frequency: "0 0 * * *",
	}
	logger := logrus.New().WithField("test", "test")

	js := NewJobScheduler(config, logger, nil)
	js.Start()
	if len(js.cronInstance.Entries()) != 0 {
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
	config := config.CryptoMonitoring{
		Enabled:   false,
		Frequency: "0 0 * * *",
	}
	logger := logrus.New().WithField("test", "test")
	job := &mockJob{}

	js := NewJobScheduler(config, logger, job)
	js.Start()
	if len(js.cronInstance.Entries()) != 0 {
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
	config := config.CryptoMonitoring{
		Enabled:   true,
		Frequency: "0 0 * * *",
	}
	logger := logrus.New().WithField("test", "test")
	job := &mockJob{}

	js := NewJobScheduler(config, logger, job)

	if js.config != config {
		t.Errorf("unexpected config, got: %v, want: %v", js.config, config)
	}

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

	config := config.CryptoMonitoring{
		Enabled:   true,
		Frequency: "0 0 * * *",
	}
	logger := logrus.New().WithField("test", "test")
	job := &mockJob{}

	js := NewJobScheduler(config, logger, job)

	js.Start()

	t.Cleanup(func() {
		js.Stop()
	})

	if js.NextRun().IsZero() {
		t.Error("expected cronInstance to be running")
	}
}

func TestJobSchedulerNextRun(t *testing.T) {
	config := config.CryptoMonitoring{
		Enabled:   true,
		Frequency: "0 0 * * *",
	}
	logger := logrus.New().WithField("test", "test")
	job := &mockJob{}

	js := NewJobScheduler(config, logger, job)
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
	config := config.CryptoMonitoring{
		Enabled:   true,
		Frequency: "0 0 * * * *",
	}
	logger := logrus.New().WithField("test", "test")
	job := &mockJob{}

	js := NewJobScheduler(config, logger, job)
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
	config := config.CryptoMonitoring{
		Enabled:   true,
		Frequency: "0 0 * * *",
	}
	logger := logrus.New().WithField("test", "test")
	job := &mockJob{}

	js := NewJobScheduler(config, logger, job)
	js.Start()
	t.Cleanup(func() {
		js.Stop()
	})

	js.Stop()

	if !js.NextRun().IsZero() {
		t.Error("expected cronInstance to be stopped")
	}
}
