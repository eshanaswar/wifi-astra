package proc

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

type Process struct {
	ID        string    `json:"id"`
	Command   string    `json:"command"`
	Args      []string  `json:"args"`
	PID       int       `json:"pid"`
	StartTime time.Time `json:"start_time"`
	Status    string    `json:"status"`
	LogFile   string    `json:"log_file"`
	cmd       *exec.Cmd
	cancel    context.CancelFunc
}

type Supervisor struct {
	processes map[string]*Process
	mu        sync.RWMutex
}

func NewSupervisor() *Supervisor {
	return &Supervisor{
		processes: make(map[string]*Process),
	}
}

func (s *Supervisor) StartProcess(id, command string, args []string, logFile string) (*Process, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// If ID is empty, generate a unique one
	if id == "" {
		id = fmt.Sprintf("proc_%d", time.Now().UnixNano())
	}

	if _, exists := s.processes[id]; exists {
		return nil, fmt.Errorf("process with ID %s already exists", id)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, command, args...)
	
	fmt.Printf("[DEBUG] Engine Supervisor: Starting %s with args %v\n", command, args)

	if logFile != "" {
		// Ensure log directory exists
		os.MkdirAll(filepath.Dir(logFile), 0755)
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err == nil {
			cmd.Stdout = f
			cmd.Stderr = f
		} else {
			fmt.Fprintf(os.Stderr, "[ERROR] Could not open log file %s: %v\n", logFile, err)
		}
	}

	if err := cmd.Start(); err != nil {
		cancel()
		return nil, err
	}

	p := &Process{
		ID:        id,
		Command:   command,
		Args:      args,
		PID:       cmd.Process.Pid,
		StartTime: time.Now(),
		Status:    "running",
		LogFile:   logFile,
		cmd:       cmd,
		cancel:    cancel,
	}

	s.processes[id] = p

	go func() {
		err := cmd.Wait()
		s.mu.Lock()
		defer s.mu.Unlock()
		if err != nil {
			p.Status = fmt.Sprintf("exited with error: %v", err)
		} else {
			p.Status = "completed"
		}
	}()

	return p, nil
}

func (s *Supervisor) StopProcess(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	p, exists := s.processes[id]
	if !exists {
		return fmt.Errorf("process %s not found", id)
	}

	if p.cmd.Process != nil {
		// Try SIGTERM first
		p.cmd.Process.Signal(syscall.SIGTERM)
		
		// Give it a moment to die
		done := make(chan struct{})
		go func() {
			p.cmd.Wait()
			close(done)
		}()

		select {
		case <-done:
		case <-time.After(3 * time.Second):
			// Force SIGKILL
			p.cmd.Process.Kill()
		}
	}

	p.cancel()
	delete(s.processes, id)
	return nil
}

func (s *Supervisor) ListProcesses() []*Process {
	s.mu.RLock()
	defer s.mu.RUnlock()

	list := make([]*Process, 0, len(s.processes))
	for _, p := range s.processes {
		list = append(list, p)
	}
	return list
}

func (s *Supervisor) Cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	for id, p := range s.processes {
		if p.cmd.Process != nil {
			p.cmd.Process.Kill()
		}
		p.cancel()
		delete(s.processes, id)
	}
}
