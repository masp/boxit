//go:build darwin

package userutil

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

// TempUser represents a temporary macOS user created for sandboxing.
type TempUser struct {
	Username string
	UID      int
	aclPaths []string // paths where ACLs were granted
}

// CreateTempUser creates a temporary macOS user with a random name.
// Requires root privileges.
func CreateTempUser() (*TempUser, error) {
	suffix, err := randomSuffix(8)
	if err != nil {
		return nil, fmt.Errorf("userutil: generate random suffix: %w", err)
	}
	username := "_boxit_" + suffix

	uid, err := findFreeUID()
	if err != nil {
		return nil, fmt.Errorf("userutil: find free UID: %w", err)
	}

	uidStr := strconv.Itoa(uid)
	userPath := "/Users/" + username

	cmds := [][]string{
		{"dscl", ".", "-create", userPath},
		{"dscl", ".", "-create", userPath, "UniqueID", uidStr},
		{"dscl", ".", "-create", userPath, "PrimaryGroupID", "20"}, // staff
		{"dscl", ".", "-create", userPath, "UserShell", "/usr/bin/false"},
		{"dscl", ".", "-create", userPath, "RealName", "boxit temp user"},
		{"dscl", ".", "-create", userPath, "NFSHomeDirectory", "/var/empty"},
	}

	for _, args := range cmds {
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			// Attempt cleanup on failure
			exec.Command("dscl", ".", "-delete", userPath).Run()
			return nil, fmt.Errorf("userutil: %s: %s: %w", args[1], strings.TrimSpace(string(out)), err)
		}
	}

	return &TempUser{Username: username, UID: uid}, nil
}

// GrantACL grants the temp user read/write/execute access to the given path
// with inheritance for child objects.
func (u *TempUser) GrantACL(path string) error {
	acl := u.Username + " allow read,write,execute,delete,append,readattr,writeattr,readextattr,writeextattr,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit"
	out, err := exec.Command("chmod", "+a", acl, path).CombinedOutput()
	if err != nil {
		return fmt.Errorf("userutil: grant ACL on %s: %s: %w", path, strings.TrimSpace(string(out)), err)
	}
	u.aclPaths = append(u.aclPaths, path)
	return nil
}

// Cleanup removes the ACLs and deletes the temporary user.
func (u *TempUser) Cleanup() error {
	var firstErr error

	// Revoke ACLs
	for _, path := range u.aclPaths {
		acl := u.Username + " allow read,write,execute,delete,append,readattr,writeattr,readextattr,writeextattr,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit"
		if out, err := exec.Command("chmod", "-a", acl, path).CombinedOutput(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("userutil: revoke ACL on %s: %s: %w", path, strings.TrimSpace(string(out)), err)
		}
	}

	// Delete user
	userPath := "/Users/" + u.Username
	if out, err := exec.Command("dscl", ".", "-delete", userPath).CombinedOutput(); err != nil && firstErr == nil {
		firstErr = fmt.Errorf("userutil: delete user %s: %s: %w", u.Username, strings.TrimSpace(string(out)), err)
	}

	return firstErr
}

func findFreeUID() (int, error) {
	// Find UIDs in the 400-499 range (system daemon range on macOS)
	out, err := exec.Command("dscl", ".", "-list", "/Users", "UniqueID").CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("list users: %w", err)
	}

	usedUIDs := make(map[int]bool)
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			if uid, err := strconv.Atoi(fields[len(fields)-1]); err == nil {
				usedUIDs[uid] = true
			}
		}
	}

	for uid := 400; uid < 500; uid++ {
		if !usedUIDs[uid] {
			return uid, nil
		}
	}
	return 0, fmt.Errorf("no free UID in range 400-499")
}

func randomSuffix(n int) (string, error) {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, n)
	for i := range result {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			return "", err
		}
		result[i] = chars[idx.Int64()]
	}
	return string(result), nil
}
