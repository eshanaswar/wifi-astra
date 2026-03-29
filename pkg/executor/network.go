package executor

import (
	"fmt"
	"os/exec"
	"wifi-astra/internal/logging"
)

// NetworkManager handles the low-level OS networking state (NAT, Routing, Forwarding)
type NetworkManager struct {
	Uplink   string
	Internal string // e.g. 192.168.44.0/24
	Gateway  string // e.g. 192.168.44.1
}

func NewNetworkManager(uplink, internal, gateway string) *NetworkManager {
	return &NetworkManager{
		Uplink:   uplink,
		Internal: internal,
		Gateway:  gateway,
	}
}

// SetupNAT configures IP forwarding and iptables MASQUERADE
func (n *NetworkManager) SetupNAT() error {
	logging.Info("Setting up NAT (Uplink: %s, Subnet: %s)...", n.Uplink, n.Internal)

	// 1. Enable IP Forwarding
	if err := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run(); err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %v", err)
	}

	// 2. Clear existing NAT rules (be surgical or cautious)
	// For now, we append our rule to ensure we don't break user state too much,
	// but in a pentest tool, we often want a clean slate.
	exec.Command("iptables", "-t", "nat", "-F").Run()
	exec.Command("iptables", "-F").Run()

	// 3. Apply Masquerade
	if err := exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-o", n.Uplink, "-j", "MASQUERADE").Run(); err != nil {
		return fmt.Errorf("failed to setup iptables MASQUERADE: %v", err)
	}

	// 4. Allow forwarding between internal and uplink
	exec.Command("iptables", "-A", "FORWARD", "-i", n.Uplink, "-o", n.Internal, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT").Run()
	exec.Command("iptables", "-A", "FORWARD", "-j", "ACCEPT").Run()

	return nil
}

// SetupInterfaceIP assigns the gateway IP to the rogue interface
func (n *NetworkManager) SetupInterfaceIP(iface string) error {
	logging.Info("Configuring IP %s on interface %s...", n.Gateway, iface)
	
	// Flush existing IPs
	exec.Command("ip", "addr", "flush", "dev", iface).Run()
	
	// Add new IP
	if err := exec.Command("ip", "addr", "add", n.Gateway+"/24", "dev", iface).Run(); err != nil {
		return fmt.Errorf("failed to assign IP to %s: %v", iface, err)
	}

	// Ensure interface is UP
	if err := exec.Command("ip", "link", "set", iface, "up").Run(); err != nil {
		return fmt.Errorf("failed to bring interface %s up: %v", iface, err)
	}

	return nil
}

// CleanupNAT restores the system to a clean state
func (n *NetworkManager) CleanupNAT() {
	logging.Info("Cleaning up NAT and routing rules...")
	exec.Command("iptables", "-t", "nat", "-F").Run()
	exec.Command("iptables", "-F").Run()
	exec.Command("sysctl", "-w", "net.ipv4.ip_forward=0").Run()
}
