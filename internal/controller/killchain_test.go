package controller

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectConnectedClientIP_LeaseFile(t *testing.T) {
	dir := t.TempDir()
	// Write a dnsmasq lease file: expiry mac ip hostname clientid
	leaseContent := "1700000000 aa:bb:cc:dd:ee:ff 192.168.44.10 android-phone *\n"
	leaseFile := filepath.Join(dir, "f1_dnsmasq.leases")
	if err := os.WriteFile(leaseFile, []byte(leaseContent), 0600); err != nil {
		t.Fatal(err)
	}
	got := DetectConnectedClientIP(dir, "F1")
	if got != "192.168.44.10" {
		t.Errorf("lease file: got %q, want 192.168.44.10", got)
	}
}

func TestDetectConnectedClientIP_LeaseFileSkipsGateway(t *testing.T) {
	dir := t.TempDir()
	leaseContent := "1700000000 aa:bb:cc:dd:ee:ff 192.168.44.1 router *\n"
	leaseFile := filepath.Join(dir, "f1_dnsmasq.leases")
	if err := os.WriteFile(leaseFile, []byte(leaseContent), 0600); err != nil {
		t.Fatal(err)
	}
	got := DetectConnectedClientIP(dir, "F1")
	if got != "" {
		t.Errorf("gateway should be skipped, got %q", got)
	}
}

func TestDetectConnectedClientIP_LogFallback(t *testing.T) {
	dir := t.TempDir()
	// No lease file — only the log file
	logContent := "Jan  1 12:00:00 host dnsmasq-dhcp[1234]: DHCPACK(wlan1) 192.168.44.20 aa:bb:cc:dd:ee:ff myhost\n"
	logFile := filepath.Join(dir, "f2_dnsmasq.log")
	if err := os.WriteFile(logFile, []byte(logContent), 0600); err != nil {
		t.Fatal(err)
	}
	got := DetectConnectedClientIP(dir, "F2")
	if got != "192.168.44.20" {
		t.Errorf("log fallback: got %q, want 192.168.44.20", got)
	}
}

func TestDetectConnectedClientIP_LogFallbackSkipsGateway(t *testing.T) {
	dir := t.TempDir()
	logContent := "Jan  1 12:00:00 host dnsmasq-dhcp[1234]: DHCPACK(wlan1) 192.168.44.1 aa:bb:cc:dd:ee:ff gw\n"
	logFile := filepath.Join(dir, "f1_dnsmasq.log")
	if err := os.WriteFile(logFile, []byte(logContent), 0600); err != nil {
		t.Fatal(err)
	}
	got := DetectConnectedClientIP(dir, "F1")
	if got != "" {
		t.Errorf("gateway should be skipped, got %q", got)
	}
}

func TestDetectConnectedClientIP_NoFiles(t *testing.T) {
	dir := t.TempDir()
	got := DetectConnectedClientIP(dir, "F1")
	if got != "" {
		t.Errorf("no files: got %q, want empty", got)
	}
}

func TestIsValidEnvKey(t *testing.T) {
	valid := []string{"FOO", "FOO_BAR", "_PRIVATE", "A1", "MONITOR_INTERFACE", "ASTRA_BIN"}
	for _, k := range valid {
		if !isValidEnvKey(k) {
			t.Errorf("expected %q to be valid", k)
		}
	}
	invalid := []string{"", "1STARTS_WITH_DIGIT", "has space", "has-dash", "has=equals", "has\nnewline", "has|pipe"}
	for _, k := range invalid {
		if isValidEnvKey(k) {
			t.Errorf("expected %q to be invalid", k)
		}
	}
}
