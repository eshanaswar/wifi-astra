package hw

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
	"wifi-astra/internal/logging"
	"wifi-astra/pkg/constants"
)

type Interface struct {
	Name    string
	Mode    string
	Driver  string
	Chipset string
}

var (
	ifaceRegex    = regexp.MustCompile(`^[a-zA-Z0-9\.\-\_]+$`)
	lockedIfaces  = make(map[string]string)
	ifaceMutex    sync.Mutex
)

// LockInterface attempts to acquire an exclusive lock on a hardware interface.
func LockInterface(iface string, moduleID string) error {
	ifaceMutex.Lock()
	defer ifaceMutex.Unlock()
	if owner, locked := lockedIfaces[iface]; locked {
		return fmt.Errorf("interface %s is currently locked by module %s", iface, owner)
	}
	lockedIfaces[iface] = moduleID
	return nil
}

// UnlockInterface releases the lock on a hardware interface.
func UnlockInterface(iface string) {
	ifaceMutex.Lock()
	defer ifaceMutex.Unlock()
	delete(lockedIfaces, iface)
}

// IsValidInterfaceName ensures the interface name doesn't contain malicious characters.
func IsValidInterfaceName(name string) bool {
	return ifaceRegex.MatchString(name)
}

func ListInterfaces() ([]Interface, error) {
	logging.Debug("Running hardware discovery (airmon-ng)...")
	cmd := exec.Command("airmon-ng")
	output, err := cmd.Output()
	
	if err != nil {
		logging.Debug("airmon-ng failed: %v. Falling back to iw.", err)
		return listInterfacesFallback()
	}

	logging.Debug("airmon-ng output: %s", string(output))

	var interfaces []Interface
	lines := strings.Split(string(output), "\n")
	
	headerFound := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		
		// Robust header detection: look for key column names regardless of spacing/tabs
		if !headerFound && strings.Contains(line, "PHY") && strings.Contains(line, "Interface") {
			headerFound = true
			continue
		}
		
		if !headerFound {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		iface := Interface{
			Name: parts[1],
		}
		if len(parts) >= 3 {
			iface.Driver = parts[2]
		}
		if len(parts) >= 4 {
			iface.Chipset = strings.Join(parts[3:], " ")
		}
		
		iface.Mode = GetInterfaceMode(iface.Name)
		interfaces = append(interfaces, iface)
	}

	if len(interfaces) == 0 {
		logging.Debug("airmon-ng returned 0 interfaces. Trying iw fallback.")
		return listInterfacesFallback()
	}

	return interfaces, nil
}

func listInterfacesFallback() ([]Interface, error) {
	logging.Debug("Running hardware discovery fallback (iw dev)...")
	cmd := exec.Command("iw", "dev")
	output, err := cmd.CombinedOutput()
	if err != nil {
		logging.Error("listInterfacesFallback: iw dev failed: %v (output: %s)", err, strings.TrimSpace(string(output)))
		return nil, fmt.Errorf("iw dev failed: %w (output: %s)", err, strings.TrimSpace(string(output)))
	}

	logging.Debug("iw dev output: %s", string(output))

	var interfaces []Interface
	var currentIface *Interface

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Interface ") {
			if currentIface != nil {
				interfaces = append(interfaces, *currentIface)
			}
			parts := strings.Fields(line)
			currentIface = &Interface{Name: parts[1]}
		} else if strings.HasPrefix(line, "type ") && currentIface != nil {
			parts := strings.Fields(line)
			currentIface.Mode = parts[1]
		}
	}
	if currentIface != nil {
		interfaces = append(interfaces, *currentIface)
	}
	return interfaces, nil
}

func GetInterfaceMode(iface string) string {
	if !IsValidInterfaceName(iface) {
		return "invalid"
	}
	cmd := exec.Command("iw", "dev", iface, "info")
	output, err := cmd.CombinedOutput()
	if err != nil {
		logging.Debug("GetInterfaceMode: iw dev %s info failed: %v (output: %s)", iface, err, strings.TrimSpace(string(output)))
		return "unknown"
	}
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "type ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return parts[1]
			}
		}
	}
	return "unknown"
}

func EnableMonitorMode(iface string) (string, error) {
	if !IsValidInterfaceName(iface) {
		return "", fmt.Errorf("invalid interface name: %s", iface)
	}

	logging.Info("Enabling monitor mode on %s...", iface)

	// Kill processes that fight with monitor mode (NetworkManager, wpa_supplicant).
	// Ignore errors — if no conflicting processes exist, this exits non-zero.
	killCmd := exec.Command("airmon-ng", "check", "kill")
	if killOut, killErr := killCmd.CombinedOutput(); killErr != nil {
		logging.Debug("airmon-ng check kill: %v (output: %s)", killErr, strings.TrimSpace(string(killOut)))
	} else {
		logging.Debug("airmon-ng check kill output: %s", strings.TrimSpace(string(killOut)))
	}

	cmd := exec.Command("airmon-ng", "start", iface)
	output, err := cmd.CombinedOutput()
	if err != nil {
		logging.Warn("airmon-ng failed: %v. Output: %s", err, string(output))
		logging.Info("Trying native kernel mode switch for %s...", iface)
		
		// Fallback to native commands
		if out, err := exec.Command("ip", "link", "set", iface, "down").CombinedOutput(); err != nil {
			return "", fmt.Errorf("failed to bring interface %s down: %v (output: %s)", iface, err, string(out))
		}
		if out, err := exec.Command("iw", "dev", iface, "set", "type", "monitor").CombinedOutput(); err != nil {
			// Restore interface before returning error
			exec.Command("ip", "link", "set", iface, "up").Run()
			return "", fmt.Errorf("failed to set monitor mode on %s: %v (output: %s)", iface, err, string(out))
		}
		if out, err := exec.Command("ip", "link", "set", iface, "up").CombinedOutput(); err != nil {
			return "", fmt.Errorf("failed to bring interface %s up: %v (output: %s)", iface, err, string(out))
		}
		return iface, nil
	}

	monIface := iface + "mon"
	if GetInterfaceMode(monIface) == "monitor" {
		return monIface, nil
	}
	
	if GetInterfaceMode(iface) == "monitor" {
		return iface, nil
	}

	ifaces, _ := ListInterfaces()
	for _, i := range ifaces {
		if i.Mode == "monitor" {
			return i.Name, nil
		}
	}

	return "", fmt.Errorf("could not identify monitor interface")
}

func DisableMonitorMode(iface string) error {
	if !IsValidInterfaceName(iface) {
		return fmt.Errorf("invalid interface name")
	}
	logging.Info("Disabling monitor mode on %s...", iface)
	
	cmd := exec.Command("airmon-ng", "stop", iface)
	output, err := cmd.CombinedOutput()
	if err != nil {
		logging.Warn("airmon-ng stop failed: %v. Output: %s", err, string(output))
		
		// Fallback: try native switch back to managed
		exec.Command("ip", "link", "set", iface, "down").Run()
		if out, err := exec.Command("iw", "dev", iface, "set", "type", "managed").CombinedOutput(); err != nil {
			exec.Command("ip", "link", "set", iface, "up").Run()
			return fmt.Errorf("failed to set managed mode on %s: %v (output: %s)", iface, err, string(out))
		}
		exec.Command("ip", "link", "set", iface, "up").Run()
	}
	return nil
}

// ScoutTarget performs a surgical 5-second background capture to identify target defenses.
func ScoutTarget(bssid string, monIface string) (map[string]string, error) {
	logging.Info("Scouting target %s for defenses...", bssid)
	
	intel := map[string]string{
		"PMF":  "None",
		"RSSI": "0",
		"AUTH": "Unknown",
	}

	// Use os.TempDir() or current directory to avoid hardcoded /tmp
	tempPcap := filepath.Join(os.TempDir(), fmt.Sprintf("astra_scout_%s.pcap", strings.ReplaceAll(bssid, ":", "")))
	defer os.Remove(tempPcap)

	// 1. Capture 5s of management frames for the BSSID
	// We use tcpdump for efficiency
	cmd := exec.Command("tcpdump", "-i", monIface, "-w", tempPcap, "-c", "50", "-n", 
		fmt.Sprintf("ether host %s and type mgt", bssid))
	
	// Run with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()
	
	if err := cmd.Start(); err != nil {
		return intel, err
	}

	go func() {
		<-ctx.Done()
		if cmd.Process != nil {
			cmd.Process.Signal(os.Interrupt)
		}
	}()
	cmd.Wait()

	if _, err := os.Stat(tempPcap); os.IsNotExist(err) {
		return intel, fmt.Errorf("no scout data captured")
	}

	// 2. Parse via tshark
	// PMF detection
	out, err := exec.Command("tshark", "-r", tempPcap, "-T", "fields", "-e", "wlan_rsn.ie.rsn.capabilities.mfpc", "-e", "wlan_rsn.ie.rsn.capabilities.mfpr").Output()
	if err == nil {
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				mfpc := parts[0]
				mfpr := parts[1]
				if mfpr == "1" {
					intel["PMF"] = "Required"
					break
				} else if mfpc == "1" {
					intel["PMF"] = "Capable"
				}
			}
		}
	}

	// RSSI detection (from first frame)
	out, err = exec.Command("tshark", "-r", tempPcap, "-T", "fields", "-e", "wlan_radio.signal_dbm", "-c", "1").Output()
	if err == nil {
		intel["RSSI"] = strings.TrimSpace(string(out))
	}

	// Auth detection
	out, err = exec.Command("tshark", "-r", tempPcap, "-T", "fields", "-e", "wlan_rsn.ie.rsn.akms", "-c", "1").Output()
	if err == nil {
		akm := strings.TrimSpace(string(out))
		if strings.Contains(akm, "8") { intel["AUTH"] = "WPA3-SAE" }
		if strings.Contains(akm, "2") { intel["AUTH"] = "WPA2-PSK" }
		if strings.Contains(akm, "1") { intel["AUTH"] = "WPA2-ENT" }
	}

	logging.Debug("Scout result for %s: %v", bssid, intel)
	return intel, nil
}

// Recover scans for interfaces stuck in monitor mode and offers to reset them.
func Recover(headless bool) {
	ifaces, err := ListInterfaces()
	if err != nil {
		return
	}

	stuck := []string{}
	for _, iface := range ifaces {
		if iface.Mode == "monitor" || strings.Contains(iface.Name, "mon") {
			stuck = append(stuck, iface.Name)
		}
	}

	if len(stuck) == 0 {
		return
	}

	if headless {
		logging.Warn("Stuck monitor interfaces detected: %v. Running in headless mode, skipping recovery.", stuck)
		return
	}

	fmt.Printf("\n%s[!] WARNING:%s %d interface(s) appear stuck in Monitor Mode: %v\n", constants.ThemeHigh, constants.ColorReset, len(stuck), stuck)
	fmt.Printf("    %sThis usually happens after an unclean exit and will break normal networking.%s\n", constants.ColorGray, constants.ColorReset)

	fmt.Printf("    %sRestore them to Managed Mode now?%s [y/N]: ", constants.ThemeHeader, constants.ColorReset)
	var response string
	fmt.Scanln(&response)

	if strings.ToLower(response) == "y" {
		for _, iface := range stuck {
			fmt.Printf("    %s[*]%s Restoring %s... ", constants.ThemeHeader, constants.ColorReset, iface)
			out, err := exec.Command("airmon-ng", "stop", iface).CombinedOutput()
			if err != nil {
				logging.Warn("airmon-ng stop %s failed: %v (output: %s)", iface, err, strings.TrimSpace(string(out)))
				fmt.Printf("%sFAILED%s (check logs)\n", constants.ThemeHigh, constants.ColorReset)
			} else {
				fmt.Printf("%sDONE%s\n", constants.ThemeSuccess, constants.ColorReset)
			}
		}
		fmt.Printf("    %s[*]%s Restart NetworkManager to restore connectivity? [y/N]: ", constants.ThemeHeader, constants.ColorReset)
		fmt.Scanln(&response)
		if strings.ToLower(response) == "y" {
			exec.Command("systemctl", "restart", "NetworkManager").Run()
			fmt.Printf("    %s[✓]%s NetworkManager restarted.\n", constants.ThemeSuccess, constants.ColorReset)
		}
	}
}
