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

