package postgres

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// deviceLockTable backs WithDeviceLock on dialects without advisory locks
// (SQLite, used for tests and single-process/dev deployments).
//
// Regression context: that fallback used to run the critical section directly,
// with no lock at all, on the reasoning that SQLite's single writer already
// serializes access. It does not — SQLite serializes individual writes, while
// WithDeviceLock's callers need a read-decide-write sequence spanning a CA round
// trip to be atomic (LWCEnroll's CR.MaximumActiveCertificates check). So the
// TOCTOU race that check exists to close was silently reopened on every
// non-Postgres deployment.
//
// The pre-existing TestCMPTx_WithDeviceLock_SerializesConcurrentCallers runs
// against real Postgres and therefore only ever exercised the advisory-lock
// path, which is why this went unnoticed. These tests exercise the fallback
// primitive itself, with no database involved.

func TestDeviceLockTable_SerializesSameKey(t *testing.T) {
	var table deviceLockTable

	const holdTime = 60 * time.Millisecond

	var mu sync.Mutex
	active, maxObserved := 0, 0
	enter := func() {
		mu.Lock()
		active++
		if active > maxObserved {
			maxObserved = active
		}
		mu.Unlock()
	}
	leave := func() {
		mu.Lock()
		active--
		mu.Unlock()
	}

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			release := table.acquire("device-shared")
			defer release()
			enter()
			time.Sleep(holdTime)
			leave()
		}()
	}
	wg.Wait()

	assert.Equal(t, 1, maxObserved,
		"concurrent acquires of the SAME device key must never overlap their critical sections")
}

func TestDeviceLockTable_DoesNotBlockDifferentKeys(t *testing.T) {
	var table deviceLockTable

	const holdTime = 200 * time.Millisecond

	held := make(chan struct{})
	done := make(chan struct{})
	go func() {
		release := table.acquire("device-a")
		close(held)
		time.Sleep(holdTime)
		release()
		close(done)
	}()

	<-held // guarantee "device-a" is held before racing for "device-b"

	start := time.Now()
	release := table.acquire("device-b")
	release()
	elapsed := time.Since(start)

	assert.Less(t, elapsed, holdTime,
		"a lock on a different device key must not wait for an unrelated key's holder")
	<-done
}

// TestDeviceLockTable_ReleasesIdleEntries pins the reference counting: the table
// must not retain an entry for every device ID it has ever seen, or a
// long-running process accumulates one mutex per enrolled device forever.
func TestDeviceLockTable_ReleasesIdleEntries(t *testing.T) {
	var table deviceLockTable

	for i := 0; i < 50; i++ {
		release := table.acquire("device-transient")
		release()
	}

	table.mu.Lock()
	remaining := len(table.locks)
	table.mu.Unlock()

	assert.Equal(t, 0, remaining, "fully released device keys must be evicted from the table")

	// While a key is genuinely held, its entry must of course still be present.
	release := table.acquire("device-held")
	table.mu.Lock()
	held := len(table.locks)
	table.mu.Unlock()
	release()
	require.Equal(t, 1, held, "a held device key must retain its entry")
}
