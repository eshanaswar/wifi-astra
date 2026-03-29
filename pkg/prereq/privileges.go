package prereq

import (
	"fmt"
	"os"
	"strconv"
)

// UserInfo stores the identity of the user who invoked the tool.
type UserInfo struct {
	UID  int
	GID  int
	Name string
}

// GetSudoUser identifies the original user if running under sudo.
func GetSudoUser() (*UserInfo, error) {
	sudoUID := os.Getenv("SUDO_UID")
	sudoGID := os.Getenv("SUDO_GID")
	sudoUser := os.Getenv("SUDO_USER")

	if sudoUID == "" || sudoGID == "" {
		return nil, fmt.Errorf("not running under sudo")
	}

	uid, _ := strconv.Atoi(sudoUID)
	gid, _ := strconv.Atoi(sudoGID)

	return &UserInfo{
		UID:  uid,
		GID:  gid,
		Name: sudoUser,
	}, nil
}

// DropPrivileges switches the process effective UID/GID back to the original user.
// DEPRECATED: Seteuid in a multi-threaded Go app causes critical privilege escalation race conditions.
// The app will now run as the invoking user (root) and use OS-level process isolation where needed.
func DropPrivileges() error {
	return nil
}

// RestorePrivileges switches back to root if needed.
// DEPRECATED: See DropPrivileges.
func RestorePrivileges() error {
	return nil
}
