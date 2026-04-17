package ui

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
	"wifi-astra/pkg/constants"
)

type ProgressMonitor struct {
	TCID      string
	StartTime time.Time
	mu        sync.Mutex
	stop      chan struct{}
	done      chan struct{}
	percent   int
	status    string
	stuck     bool
}

func NewProgressMonitor(tcID string) *ProgressMonitor {
	return &ProgressMonitor{
		TCID:      tcID,
		StartTime: time.Now(),
		stop:      make(chan struct{}),
		done:      make(chan struct{}),
	}
}

func (pm *ProgressMonitor) Start(updateFunc func() (int, string, bool)) {
	ticker := time.NewTicker(1 * time.Second)
	go func() {
		defer close(pm.done)
		for {
			select {
			case <-pm.stop:
				pm.clearBar()
				ticker.Stop()
				return
			case <-ticker.C:
				p, s, stuck := updateFunc()
				pm.mu.Lock()
				pm.percent = p
				pm.status = s
				pm.stuck = stuck
				pm.mu.Unlock()
				pm.renderBar() // called AFTER releasing lock to avoid reentrant deadlock
			}
		}
	}()
}

func (pm *ProgressMonitor) Stop() {
	close(pm.stop)
	<-pm.done // wait for goroutine to exit
}

func (pm *ProgressMonitor) renderBar() {
	// Read fields under lock, then render outside the lock to prevent
	// reentrant deadlock when called from the Start() goroutine.
	pm.mu.Lock()
	p := pm.percent
	s := pm.status
	stuck := pm.stuck
	startTime := pm.StartTime
	pm.mu.Unlock()

	// SILENCE GUARD: Do not render if we are still initializing
	if p == 0 && s == "" {
		return
	}

	width := 40
	bar := ""
	percentStr := fmt.Sprintf("%d%%", p)
	statusPrefix := "RUNNING"

	if os.Getenv("ASTRA_INDEFINITE") == "true" {
		statusPrefix = "INDEFINITE"
		percentStr = "∞"
		// Animated sliding bar for indefinite mode
		pos := int(time.Since(startTime).Seconds()) % width
		bar = strings.Repeat(" ", pos) + "🛰️" + strings.Repeat(" ", width-pos-2)
		if len(bar) > width {
			bar = bar[:width]
		}
	} else {
		completed := (p * width) / 100
		if completed > width {
			completed = width
		}
		bar = strings.Repeat("█", completed) + strings.Repeat("░", width-completed)
	}

	color := constants.ThemeInfo
	if stuck && os.Getenv("ASTRA_INDEFINITE") != "true" {
		color = constants.ThemeHigh
		statusPrefix = "STUCK?"
	} else if p >= 100 {
		color = constants.ThemeSuccess
		statusPrefix = "FINISHING"
	}

	elapsed := time.Since(startTime).Round(time.Second)

	fmt.Printf("\033[s\033[1000;1H\033[K%s[%s]%s [%s] %s %s | %s\033[u",
		color, statusPrefix, constants.ColorReset,
		bar, percentStr, s, elapsed)
}

func (pm *ProgressMonitor) clearBar() {
	fmt.Print("\033[s\033[1000;1H\033[K\033[u")
}
