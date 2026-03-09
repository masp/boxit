//go:build darwin

package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

const profile = `(version 1)
(allow default)

;; Deny all file writes
(deny file-write*)

;; Allow writes to CWD (parameterized)
(allow file-write* (subpath (param "CWD")))

;; Allow writes to system temp dirs (symlink-resolved paths)
(allow file-write*
    (subpath "/private/tmp")
    (subpath "/private/var/folders")
)

;; Allow writes to device nodes (/dev/null, /dev/tty, /dev/fd for process substitution)
(allow file-write* (subpath "/dev"))

;; Block SSH (port 22) — prevents git push over SSH, allows HTTPS clone/fetch
(deny network-outbound (remote tcp "*:22"))
`

// Options configures the sandbox execution.
type Options struct {
	CWD      string
	Args     []string
	RunAsUID int      // 0 = current user (no proxy mode)
	ExtraEnv []string // additional env vars (e.g. cert trust vars)
}

// Run executes a command inside a macOS sandbox-exec sandbox.
// This is the simple form that runs as the current user.
func Run(cwd string, args []string) error {
	return RunWithOptions(Options{CWD: cwd, Args: args})
}

// RunWithOptions executes a command inside a macOS sandbox-exec sandbox
// with the given options.
func RunWithOptions(opts Options) error {
	cwd, err := filepath.EvalSymlinks(opts.CWD)
	if err != nil {
		return err
	}

	sandboxExec, err := exec.LookPath("sandbox-exec")
	if err != nil {
		return err
	}

	sandboxArgs := []string{"-D", "CWD=" + cwd, "-p", profile}
	sandboxArgs = append(sandboxArgs, opts.Args...)

	var cmd *exec.Cmd
	if opts.RunAsUID > 0 {
		// Find the username for this UID
		username, err := usernameForUID(opts.RunAsUID)
		if err != nil {
			return fmt.Errorf("sandbox: %w", err)
		}
		// Wrap with sudo -u <user> to run as the temp user.
		// Use 'env' to pass extra env vars since sudo resets the environment.
		sudoArgs := []string{"-u", username, "--"}
		if len(opts.ExtraEnv) > 0 {
			sudoArgs = append(sudoArgs, "env")
			sudoArgs = append(sudoArgs, opts.ExtraEnv...)
		}
		sudoArgs = append(sudoArgs, sandboxExec)
		sudoArgs = append(sudoArgs, sandboxArgs...)
		cmd = exec.Command("sudo", sudoArgs...)
	} else {
		cmd = exec.Command(sandboxExec, sandboxArgs...)
	}

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Dir = cwd

	if len(opts.ExtraEnv) > 0 && opts.RunAsUID == 0 {
		cmd.Env = append(os.Environ(), opts.ExtraEnv...)
	}

	return cmd.Run()
}

func usernameForUID(uid int) (string, error) {
	out, err := exec.Command("id", "-un", fmt.Sprintf("%d", uid)).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("lookup uid %d: %w", uid, err)
	}
	name := string(out)
	// Trim trailing newline
	if len(name) > 0 && name[len(name)-1] == '\n' {
		name = name[:len(name)-1]
	}
	return name, nil
}
