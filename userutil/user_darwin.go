//go:build darwin

package userutil

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// aclGrant records an ACL that was granted so it can be revoked on cleanup.
type aclGrant struct {
	path string
	acl  string
}

// TempUser represents a temporary macOS user created for sandboxing.
type TempUser struct {
	Username string
	UID      int
	acls     []aclGrant // ACLs granted (to revoke on cleanup)
	conn     net.Conn   // connection to the daemon
}

func connectToDaemon() (net.Conn, error) {
	conn, err := net.Dial("unix", SocketPath)
	if err == nil {
		return conn, nil
	}

	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("find executable: %w", err)
	}

	cmd := exec.Command(exe, "daemon")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start daemon: %w", err)
	}

	for i := 0; i < 20; i++ {
		time.Sleep(100 * time.Millisecond)
		conn, err = net.Dial("unix", SocketPath)
		if err == nil {
			return conn, nil
		}
	}
	return nil, fmt.Errorf("daemon failed to start or bind socket: %v", err)
}

// CreateTempUser creates a temporary macOS user with a random name.
// Requires root privileges.
func CreateTempUser() (*TempUser, error) {
	conn, err := connectToDaemon()
	if err != nil {
		return nil, err
	}

	if _, err := conn.Write([]byte("ALLOC\n")); err != nil {
		conn.Close()
		return nil, fmt.Errorf("userutil: request alloc: %w", err)
	}

	var rep reply
	if err := json.NewDecoder(conn).Decode(&rep); err != nil {
		conn.Close()
		return nil, fmt.Errorf("userutil: read daemon reply: %w", err)
	}

	if rep.Error != "" {
		conn.Close()
		return nil, fmt.Errorf("userutil: daemon error: %s", rep.Error)
	}

	return &TempUser{Username: rep.Username, UID: rep.UID, conn: conn}, nil
}

func createTempUserInternal() (string, int, error) {
	suffix, err := randomSuffix(8)
	if err != nil {
		return "", 0, fmt.Errorf("userutil: generate random suffix: %w", err)
	}
	username := "_boxit_" + suffix

	uid, err := findFreeUID()
	if err != nil {
		return "", 0, fmt.Errorf("userutil: find free UID: %w", err)
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
			return "", 0, fmt.Errorf("userutil: %s: %s: %w", args[1], strings.TrimSpace(string(out)), err)
		}
	}

	return username, uid, nil
}

// GrantACL grants the temp user read/write/execute access to the given path
// with inheritance for child objects. It also grants minimal traverse (search)
// permission on parent directories that are not world-executable, so the temp
// user can reach the target path.
func (u *TempUser) GrantACL(path string) error {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		resolved = path
	}

	acl := u.Username + " allow read,write,execute,delete,append,readattr,writeattr,readextattr,writeextattr,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit"
	out, err := exec.Command("chmod", "+a", acl, resolved).CombinedOutput()
	if err != nil {
		return fmt.Errorf("userutil: grant ACL on %s: %s: %w", path, strings.TrimSpace(string(out)), err)
	}
	u.acls = append(u.acls, aclGrant{resolved, acl})

	// Ensure parent directories are traversable by adding the world-execute
	// bit. This is needed when parents have restrictive permissions (e.g. 0700
	// temp dirs) that prevent the temp user from reaching the CWD.
	dir := filepath.Dir(resolved)
	for dir != "/" && dir != "." {
		info, err := os.Stat(dir)
		if err != nil {
			break
		}
		perm := info.Mode().Perm()
		if perm&0o001 != 0 {
			break // already world-traversable
		}
		os.Chmod(dir, perm|0o001) // best-effort
		dir = filepath.Dir(dir)
	}

	return nil
}

// Cleanup removes the ACLs and deletes the temporary user.
func (u *TempUser) Cleanup() error {
	var firstErr error

	// Revoke ACLs
	for _, g := range u.acls {
		if out, err := exec.Command("chmod", "-a", g.acl, g.path).CombinedOutput(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("userutil: revoke ACL on %s: %s: %w", g.path, strings.TrimSpace(string(out)), err)
		}
	}

	// The daemon will delete the user when we close the connection
	if u.conn != nil {
		if err := u.conn.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("userutil: close daemon connection: %w", err)
		}
	}

	return firstErr
}

func cleanupTempUserInternal(username string) error {
	userPath := "/Users/" + username
	if out, err := exec.Command("dscl", ".", "-delete", userPath).CombinedOutput(); err != nil {
		return fmt.Errorf("userutil: delete user %s: %s: %w", username, strings.TrimSpace(string(out)), err)
	}
	return nil
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
