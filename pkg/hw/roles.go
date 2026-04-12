package hw

import (
	"fmt"
	"sync"
)

// InterfaceRole identifies the operational role of a wireless adapter.
type InterfaceRole int

const (
	RoleMonitor    InterfaceRole = iota // Injection and capture — used by attack modules
	RoleManagement                      // Internet/C2 — never touched by attack modules
)

// RoleRegistry maps roles to interface names and enforces that the management
// interface cannot be used for monitor-mode operations.
type RoleRegistry struct {
	mu     sync.RWMutex
	roles  map[InterfaceRole]string
	locked bool
}

// NewRoleRegistry creates an empty registry. Call Assign() for each role,
// then Lock() before starting the session.
func NewRoleRegistry() *RoleRegistry {
	return &RoleRegistry{
		roles: make(map[InterfaceRole]string),
	}
}

// Assign sets the interface for the given role. Returns an error if the
// registry is locked or if the interface is already assigned to another role.
func (r *RoleRegistry) Assign(role InterfaceRole, iface string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.locked {
		return fmt.Errorf("role registry is locked — cannot reassign roles after session start")
	}

	// Prevent the same interface being assigned to two roles
	for existingRole, existingIface := range r.roles {
		if existingIface == iface && existingRole != role {
			return fmt.Errorf("interface %s is already assigned to role %d", iface, existingRole)
		}
	}

	r.roles[role] = iface
	return nil
}

// Lock freezes the registry. After locking, Assign() returns an error.
// Call this once both roles are configured and the session has started.
func (r *RoleRegistry) Lock() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.locked = true
}

// Get returns the interface name for the given role.
// Returns an error if the role has not been assigned.
func (r *RoleRegistry) Get(role InterfaceRole) (string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	iface, ok := r.roles[role]
	if !ok {
		return "", fmt.Errorf("no interface assigned for role %d", role)
	}
	return iface, nil
}

// AssertMonitor verifies that iface is the MONITOR interface.
// Returns an error if iface is the management interface (protecting it from attacks)
// or if roles have not been assigned.
func (r *RoleRegistry) AssertMonitor(iface string) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	mon, ok := r.roles[RoleMonitor]
	if !ok {
		return fmt.Errorf("monitor interface role not assigned")
	}
	mgmt, mgmtAssigned := r.roles[RoleManagement]

	if mgmtAssigned && iface == mgmt {
		return fmt.Errorf("SAFETY: interface %s is the management interface and cannot be used for attack operations", iface)
	}
	if iface != mon {
		return fmt.Errorf("interface %s is not the assigned monitor interface (%s)", iface, mon)
	}
	return nil
}

// IsManagement returns true if iface is the assigned management interface.
func (r *RoleRegistry) IsManagement(iface string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	mgmt, ok := r.roles[RoleManagement]
	return ok && mgmt == iface
}
