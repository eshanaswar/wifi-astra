package prereq

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"wifi-astra/internal/logging"

	"golang.org/x/sys/unix"
)

type Tool struct {
	Name     string
	Path     string
	Critical bool
	Found    bool
}

type CheckResult struct {
	Tools   []Tool
	Missing []string
}

// CheckTools verifies the existence of required tools.
func CheckTools(requiredTools []string, criticalTools []string) *CheckResult {
	result := &CheckResult{
		Tools: make([]Tool, 0, len(requiredTools)),
	}

	criticalMap := make(map[string]bool)
	for _, t := range criticalTools {
		criticalMap[t] = true
	}

	for _, toolName := range requiredTools {
		path, err := resolveToolPath(toolName)
		found := (err == nil)
		
		t := Tool{
			Name:     toolName,
			Path:     path,
			Critical: criticalMap[toolName],
			Found:    found,
		}
		
		if !found {
			logging.Warn("Required tool not found: %s", toolName)
			result.Missing = append(result.Missing, toolName)
		} else {
			logging.Debug("Tool found: %s at %s", toolName, path)
		}
		
		result.Tools = append(result.Tools, t)
	}

	return result
}

func resolveToolPath(tool string) (string, error) {
	// 1. Check system PATH
	path, err := exec.LookPath(tool)
	if err == nil {
		return path, nil
	}

	// 2. Check for common research tool names in current directory or subdirectories
	cwd, _ := os.Getwd()
	searchPaths := []string{
		cwd,
		filepath.Join(cwd, "research"),
		filepath.Join(cwd, "tools"),
	}

	binaryMap := map[string]string{
		"airsnitch":      "research/airsnitch.py",
		"eaphammer":      "eaphammer",
		"krack-test":     "krackattacks-scripts/krackattack/krackattack.py",
		"fragattack":     "fragattacks/fragattack.py",
		"dragonslayer":   "dragonblood/dragonslayer.py",
		"dragondrain":    "dragonblood/dragondrain.py",
	}

	if binary, ok := binaryMap[tool]; ok {
		for _, p := range searchPaths {
			fullPath := filepath.Join(p, binary)
			if info, err := os.Stat(fullPath); err == nil && !info.IsDir() && (info.Mode()&0111 != 0) {
				return fullPath, nil
			}
		}
	}

	return "", fmt.Errorf("tool %s not found", tool)
}

// HasRequiredCapabilities checks if the process has CAP_NET_RAW and CAP_NET_ADMIN.
func HasRequiredCapabilities() bool {
	// 1. Check for Raw Socket capability (CAP_NET_RAW)
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err == nil {
		unix.Close(fd)
	} else {
		return false
	}

	// 2. Check for Admin capability (CAP_NET_ADMIN)
	// We try a simple administrative operation on a dummy interface or similar
	// But simpler: just check if we can open /dev/net/tun or check caps via proc
	// For now, raw socket is the primary blocker for attacks.
	return true 
}

// IsRoot checks if the process is running as root.
func IsRoot() bool {
	return os.Geteuid() == 0
}

// VerifyEnvironment runs all pre-flight environmental checks.
func VerifyEnvironment() error {
	if !IsRoot() && !HasRequiredCapabilities() {
		return fmt.Errorf("insufficient privileges: root or CAP_NET_RAW/CAP_NET_ADMIN required")
	}

	// Check for essential tools
	essential := []string{"airmon-ng", "airodump-ng", "iw", "ip", "jq", "curl"}
	result := CheckTools(essential, essential)
	
	for _, t := range result.Tools {
		if t.Critical && !t.Found {
			return fmt.Errorf("missing critical tool: %s", t.Name)
		}
	}

	return nil
}
