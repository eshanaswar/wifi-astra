package ui

import (
	"fmt"
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
	completed := (pm.percent * width) / 100
	if completed > width { completed = width }
	
	bar := strings.Repeat("█", completed) + strings.Repeat("░", width-completed)
	
	color := constants.ThemeInfo
	statusPrefix := "RUNNING"
	if pm.stuck {
		color = constants.ThemeHigh
		statusPrefix = "STUCK?"
	} else if pm.percent >= 100 {
		color = constants.ThemeSuccess
		statusPrefix = "FINISHING"
	}

	elapsed := time.Since(pm.StartTime).Round(time.Second)
	
	// Move to bottom of terminal (standard hack: save, jump to big row, print, restore)
	// Actually, we'll just print it on the current line but use \r to keep it updated 
	// IF there are no logs. But since there are logs, we MUST use save/restore.
	
	fmt.Printf("\033[s\033[1000;1H\033[K%s[%s]%s [%s] %d%% %s | %s\033[u", 
		color, statusPrefix, constants.ColorReset, 
		bar, pm.percent, pm.status, elapsed)
}

func (pm *ProgressMonitor) clearBar() {
	fmt.Print("\033[s\033[1000;1H\033[K\033[u")
}
