package hw

import (
	"fmt"
	"os/exec"
	"strings"

	"wifi-astra/internal/logging"
)

// DetectUplinkInterface returns the interface used for the default route by
// inspecting `ip route get 8.8.8.8`. Output format:
//
//	8.8.8.8 via 192.168.1.1 dev eth0 src 192.168.1.100 uid 0
func DetectUplinkInterface() (string, error) {
	out, err := exec.Command("ip", "route", "get", "8.8.8.8").Output()
	if err != nil {
		return "", fmt.Errorf("ip route get 8.8.8.8 failed: %w", err)
	}
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			iface := fields[i+1]
			if IsValidInterfaceName(iface) {
				return iface, nil
			}
		}
	}
	return "", fmt.Errorf("could not parse uplink interface from: %s", strings.TrimSpace(string(out)))
}

// SetupNAT enables IPv4 forwarding and installs an iptables masquerade rule on
// uplinkIface. The rule is idempotent — if it already exists it is left in place.
// Called by the controller before launching any module whose MODULE_META REQS
// field contains "nat" (F1, F2, F3).
func SetupNAT(uplinkIface string) error {
	if !IsValidInterfaceName(uplinkIface) {
		return fmt.Errorf("invalid uplink interface name: %s", uplinkIface)
	}

	// Enable IP forwarding
	if out, err := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").CombinedOutput(); err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %w (%s)", err, strings.TrimSpace(string(out)))
	}

	// Check whether the masquerade rule already exists (-C exits 1 if absent)
	checkErr := exec.Command("iptables", "-t", "nat", "-C", "POSTROUTING",
		"-o", uplinkIface, "-j", "MASQUERADE").Run()
	if checkErr != nil {
		// Rule absent — add it
		if out, err := exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING",
			"-o", uplinkIface, "-j", "MASQUERADE").CombinedOutput(); err != nil {
			return fmt.Errorf("failed to add iptables masquerade rule on %s: %w (%s)",
				uplinkIface, err, strings.TrimSpace(string(out)))
		}
		logging.Info("NAT masquerade enabled on %s", uplinkIface)
	} else {
		logging.Info("NAT masquerade already active on %s (rule already present)", uplinkIface)
	}
	return nil
}

// TeardownNAT removes the masquerade rule added by SetupNAT. Errors are logged
// but not returned — teardown must not block session cleanup. IP forwarding is
// intentionally left enabled; turning it off mid-session could disrupt other routing.
func TeardownNAT(uplinkIface string) {
	if !IsValidInterfaceName(uplinkIface) {
		logging.Warn("TeardownNAT: invalid interface name: %s", uplinkIface)
		return
	}
	if err := exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING",
		"-o", uplinkIface, "-j", "MASQUERADE").Run(); err != nil {
		logging.Warn("TeardownNAT: could not remove masquerade rule on %s: %v", uplinkIface, err)
	} else {
		logging.Info("NAT masquerade removed from %s", uplinkIface)
	}
}
