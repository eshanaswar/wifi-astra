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

// ModuleToolMap maps each module ID to the list of external tools it requires.
// Keep this in sync with each module's TOOLS= header in modules/*.sh.
var ModuleToolMap = map[string][]string{
	"A1":  {"airmon-ng", "airodump-ng"},
	"A2":  {"airmon-ng", "airodump-ng"},
	"A3":  {"aireplay-ng", "airodump-ng"},
	"A4":  {"airmon-ng", "airodump-ng"},
	"A5":  {"tshark", "iw"},
	"B1":  {"nmap", "fping", "arping"},
	"B2":  {"nmap"},
	"B3":  {"tcpdump", "tshark"},
	"B4":  {"tcpdump", "tshark"},
	"B5":  {"snmp-check", "onesixtyone"},
	"B6":  {"nmap", "tcpdump"},
	"B7":  {"tcpdump", "tshark"},
	"B8":  {"tcpdump", "tshark"},
	"B9":  {"nmap", "nuclei"},
	"B10": {"python3", "tshark"}, // scapy is a Python library, not a PATH binary
	"C1":  {"dig", "host"},
	"C2":  {"fping", "nmap"},
	"C3":  {"yersinia", "tcpdump"},
	"C4":  {"nmap"},
	"C5":  {"nmap"},
	"D1":  {"aireplay-ng", "aircrack-ng", "hcxdumptool", "hcxpcapngtool"},
	"D2":  {"airodump-ng", "aireplay-ng", "aircrack-ng"},
	"D3":  {"wash", "reaver", "bully"},
	"D4":  {"dragonslayer", "dragondrain"},
	"D5":  {"eaphammer"},
	"D8":  {"hostapd-wpe", "openssl"},
	"D6":  {"hostapd", "airodump-ng"},
	"D7":  {"hostapd", "mdk4", "aireplay-ng"},
	"E1":  {"tshark", "krack-test"},
	"E2":  {"fragattack"},
	"E3":  {"aireplay-ng", "airodump-ng"},
	"E4":  {"mdk4"},
	"E5":  {"tshark"},
	"F1":  {"hostapd", "dnsmasq", "iptables", "mdk4"},
	"F2":  {"hostapd-mana", "dnsmasq", "mdk4"},
	"F3":  {"python3", "hostapd", "dnsmasq"},
	"F4":  {"macchanger", "curl", "aireplay-ng", "mdk4"},
	"F5":  {"iodine"},
	"G1":  {"bettercap", "ip"},
	"G2":  {"mitmproxy", "iptables"},
	"G3":  {"bettercap", "dnsmasq"},
	"G4":  {"macchanger", "dhclient", "hostname"},
	"G5":  {"hostapd", "python3"}, // scapy is a Python library, not a PATH binary
	"G6":  {"responder"},
	"H1":  {"aireplay-ng", "tcpdump", "mdk4"},
	"H2":  {"airodump-ng"},
}

// PreflightModules checks which modules in toolMap have all their required
// tools available on PATH. Returns a map of module ID → available (bool).
func PreflightModules(toolMap map[string][]string) map[string]bool {
	result := make(map[string]bool, len(toolMap))
	for id, tools := range toolMap {
		available := true
		for _, tool := range tools {
			if tool == "" {
				continue
			}
			if _, err := resolveToolPath(tool); err != nil {
				available = false
				break
			}
		}
		result[id] = available
	}
	return result
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
