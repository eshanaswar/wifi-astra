package executor

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
	"wifi-astra/internal/logging"
)

type Process struct {
	ID        string    `json:"id"`
	Command   string    `json:"command"`
	Args      []string  `json:"args"`
	PID       int       `json:"pid"`
	StartTime time.Time `json:"start_time"`
	Status    string    `json:"status"`
	LogFile   string    `json:"log_file"`
	ExitCode  int       `json:"exit_code"`
	cmd       *exec.Cmd
	cancel    context.CancelFunc
}

type Manager struct {
	processes map[string]*Process
	mu        sync.RWMutex
}

func NewManager() *Manager {
	return &Manager{
		processes: make(map[string]*Process),
	}
}

// Run executes a command in the foreground and waits for it to finish.
func (m *Manager) Run(ctx context.Context, id, command string, args []string, logFile string) (int, error) {
	return m.RunWithEnv(ctx, id, command, args, logFile, os.Environ())
}

// RunWithEnv executes a command in the foreground with a custom environment.
func (m *Manager) RunWithEnv(ctx context.Context, id, command string, args []string, logFile string, env []string) (int, error) {
	logging.Info("Executing: %s %v", command, args)
	
	p, err := m.start(ctx, id, command, args, logFile, env)
	if err != nil {
		return -1, err
	}

	err = p.cmd.Wait()
	m.mu.Lock()
	defer m.mu.Unlock()

	p.Status = "completed"
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			p.ExitCode = exitErr.ExitCode()
			p.Status = fmt.Sprintf("failed (exit code %d)", p.ExitCode)
		} else {
			p.Status = fmt.Sprintf("error: %v", err)
			return -1, err
		}
	} else {
		p.ExitCode = 0
	}

	delete(m.processes, p.ID)
	return p.ExitCode, nil
}

// Spawn executes a command in the background.
func (m *Manager) Spawn(ctx context.Context, id, command string, args []string, logFile string) (*Process, error) {
	return m.SpawnWithEnv(ctx, id, command, args, logFile, os.Environ())
}

// SpawnWithEnv executes a command in the background with a custom environment.
func (m *Manager) SpawnWithEnv(ctx context.Context, id, command string, args []string, logFile string, env []string) (*Process, error) {
	logging.Info("Spawning background process: %s %v", command, args)
	p, err := m.start(ctx, id, command, args, logFile, env)
	if err != nil {
		return nil, err
	}

	go func() {
		err := p.cmd.Wait()
		m.mu.Lock()
		defer m.mu.Unlock()
		
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				p.ExitCode = exitErr.ExitCode()
				p.Status = fmt.Sprintf("failed (exit code %d)", p.ExitCode)
			} else {
				p.Status = fmt.Sprintf("error: %v", err)
			}
		} else {
			p.Status = "completed"
			p.ExitCode = 0
		}
	}()

	return p, nil
}

func (m *Manager) start(ctx context.Context, id, command string, args []string, logFile string, env []string) (*Process, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if id == "" {
		id = fmt.Sprintf("proc_%d", time.Now().UnixNano())
	}

	if _, exists := m.processes[id]; exists {
		return nil, fmt.Errorf("process with ID %s already exists", id)
	}

	innerCtx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(innerCtx, command, args...)
	cmd.Env = env

	// Create a new process group so we can kill children properly
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if logFile != "" {
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err == nil {
			cmd.Stdout = io.MultiWriter(os.Stdout, f)
			cmd.Stderr = io.MultiWriter(os.Stderr, f)
		} else {
			logging.Error("Could not open log file %s: %v", logFile, err)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
		}
	} else {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	cmd.Stdin = os.Stdin // Enable interactive input for modules

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

	m.processes[id] = p
	return p, nil
}

func (m *Manager) Stop(id string) error {
	m.mu.Lock()
	p, exists := m.processes[id]
	m.mu.Unlock()

	if !exists {
		return fmt.Errorf("process %s not found", id)
	}

	logging.Info("Stopping process %s (PID: %d)...", id, p.PID)

	// Cancel the context to stop the process
	p.cancel()

	// Kill the entire process group
	pgid, err := syscall.Getpgid(p.PID)
	if err == nil {
		syscall.Kill(-pgid, syscall.SIGTERM)
		
		// Give it a moment to die gracefully
		time.Sleep(500 * time.Millisecond)
		
		// If it's still there, force it
		syscall.Kill(-pgid, syscall.SIGKILL)
	}

	m.mu.Lock()
	delete(m.processes, id)
	m.mu.Unlock()
	
	return nil
}

func (m *Manager) Cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for id, p := range m.processes {
		logging.Debug("Cleanup: Killing process %s (PID: %d)", id, p.PID)
		pgid, err := syscall.Getpgid(p.PID)
		if err == nil {
			syscall.Kill(-pgid, syscall.SIGKILL)
		}
		p.cancel()
		delete(m.processes, id)
	}
}
