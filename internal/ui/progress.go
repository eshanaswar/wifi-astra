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
	percent   int
	status    string
	stuck     bool
}

func NewProgressMonitor(tcID string) *ProgressMonitor {
	return &ProgressMonitor{
		TCID:      tcID,
		StartTime: time.Now(),
		stop:      make(chan struct{}),
	}
}

func (pm *ProgressMonitor) Start(updateFunc func() (int, string, bool)) {
	ticker := time.NewTicker(1 * time.Second)
	go func() {
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
				pm.renderBar()
				pm.mu.Unlock()
			}
		}
	}()
}

func (pm *ProgressMonitor) Stop() {
	close(pm.stop)
	// Give it a moment to clear
	time.Sleep(100 * time.Millisecond)
}

func (pm *ProgressMonitor) renderBar() {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	// SILENCE GUARD: Do not render if we are still initializing
	if pm.percent == 0 && pm.status == "" {
		return
	}

	width := 40
	bar := ""
	percentStr := fmt.Sprintf("%d%%", pm.percent)
	statusPrefix := "RUNNING"
	
	if os.Getenv("ASTRA_INDEFINITE") == "true" {
		statusPrefix = "INDEFINITE"
		percentStr = "∞"
		// Animated sliding bar for indefinite mode
		pos := int(time.Since(pm.StartTime).Seconds()) % width
		bar = strings.Repeat(" ", pos) + "🛰️" + strings.Repeat(" ", width-pos-2)
		if len(bar) > width { bar = bar[:width] }
	} else {
		completed := (pm.percent * width) / 100
		if completed > width { completed = width }
		bar = strings.Repeat("█", completed) + strings.Repeat("░", width-completed)
	}
	
	color := constants.ThemeInfo
	if pm.stuck && os.Getenv("ASTRA_INDEFINITE") != "true" {
		color = constants.ThemeHigh
		statusPrefix = "STUCK?"
	} else if pm.percent >= 100 {
		color = constants.ThemeSuccess
		statusPrefix = "FINISHING"
	}

	elapsed := time.Since(pm.StartTime).Round(time.Second)
	
	fmt.Printf("\033[s\033[1000;1H\033[K%s[%s]%s [%s] %s %s | %s\033[u", 
		color, statusPrefix, constants.ColorReset, 
		bar, percentStr, pm.status, elapsed)
}

func (pm *ProgressMonitor) clearBar() {
	fmt.Print("\033[s\033[1000;1H\033[K\033[u")
}
