package hw

import (
	"testing"
)

func TestRoleRegistryAssignAndGet(t *testing.T) {
	r := NewRoleRegistry()
	r.Assign(RoleMonitor, "wlan0")
	r.Assign(RoleManagement, "wlan1")

	mon, err := r.Get(RoleMonitor)
	if err != nil {
		t.Fatalf("expected monitor interface, got error: %v", err)
	}
	if mon != "wlan0" {
		t.Errorf("expected wlan0, got %s", mon)
	}

	mgmt, err := r.Get(RoleManagement)
	if err != nil {
		t.Fatalf("expected management interface, got error: %v", err)
	}
	if mgmt != "wlan1" {
		t.Errorf("expected wlan1, got %s", mgmt)
	}
}

func TestRoleRegistryGetUnassigned(t *testing.T) {
	r := NewRoleRegistry()
	_, err := r.Get(RoleMonitor)
	if err == nil {
		t.Fatal("expected error for unassigned role, got nil")
	}
}

func TestRoleRegistryAssertMonitor(t *testing.T) {
	r := NewRoleRegistry()
	r.Assign(RoleMonitor, "wlan0")
	r.Assign(RoleManagement, "wlan1")

	// Monitor interface passes assertion
	if err := r.AssertMonitor("wlan0"); err != nil {
		t.Errorf("expected wlan0 to pass AssertMonitor: %v", err)
	}

	// Management interface fails assertion
	if err := r.AssertMonitor("wlan1"); err == nil {
		t.Error("expected wlan1 to fail AssertMonitor (it is the management interface)")
	}
}

func TestRoleRegistryIsManagement(t *testing.T) {
	r := NewRoleRegistry()
	r.Assign(RoleMonitor, "wlan0")
	r.Assign(RoleManagement, "wlan1")

	if !r.IsManagement("wlan1") {
		t.Error("expected wlan1 to be identified as management interface")
	}
	if r.IsManagement("wlan0") {
		t.Error("expected wlan0 to not be identified as management interface")
	}
}

func TestRoleRegistryAssignRejectsDuplicateInterface(t *testing.T) {
	// The same physical interface cannot be assigned to two different roles.
	// This guard is independent of locking.
	r := NewRoleRegistry()
	if err := r.Assign(RoleMonitor, "wlan0"); err != nil {
		t.Fatalf("first assign failed: %v", err)
	}
	// Attempting to assign the same interface to a different role must fail
	err := r.Assign(RoleManagement, "wlan0")
	if err == nil {
		t.Error("expected error when assigning same interface to a second role")
	}
}

func TestRoleRegistryAssertMonitorSingleAdapter(t *testing.T) {
	// With only RoleMonitor assigned (no management interface), AssertMonitor
	// should still pass for the monitor interface — single-adapter setup.
	r := NewRoleRegistry()
	r.Assign(RoleMonitor, "wlan0")

	if err := r.AssertMonitor("wlan0"); err != nil {
		t.Errorf("expected wlan0 to pass AssertMonitor on single-adapter setup: %v", err)
	}
}

func TestRoleRegistryLocksPreventsReassign(t *testing.T) {
	r := NewRoleRegistry()
	r.Assign(RoleMonitor, "wlan0")
	r.Lock()

	// The registry is locked — this should return an error
	err := r.Assign(RoleManagement, "wlan0")
	if err == nil {
		t.Error("expected error when assigning after lock")
	}
}
