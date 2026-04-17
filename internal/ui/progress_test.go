package ui

import (
	"testing"
	"time"
)

func TestProgressMonitorRendersWithoutDeadlock(t *testing.T) {
	pm := NewProgressMonitor("TEST")

	// Count how many times updateFunc is called.
	// If the goroutine deadlocks after the first tick, callCount stays at 1.
	// A healthy implementation calls it on every tick.
	callCount := make(chan int, 10)

	pm.Start(func() (int, string, bool) {
		callCount <- 1
		return 42, "working", false
	})

	// Wait for at least 2 calls (proves goroutine is NOT deadlocked after first tick)
	total := 0
	deadline := time.After(5 * time.Second)
	for total < 2 {
		select {
		case <-callCount:
			total++
		case <-deadline:
			t.Fatalf("updateFunc called only %d time(s) in 5s — goroutine likely deadlocked after first tick", total)
		}
	}

	pm.Stop()
}

func TestProgressMonitorStopsCleanly(t *testing.T) {
	pm := NewProgressMonitor("TEST2")
	pm.Start(func() (int, string, bool) { return 50, "running", false })
	done := make(chan struct{})
	go func() {
		pm.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("pm.Stop() did not return within 2s")
	}
}
