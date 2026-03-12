//go:build linux

package sandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

var traceEnabled bool

// SetTrace enables sandbox tracing globally (no-op on Linux; overlay is transparent).
func SetTrace(enabled bool) {
	traceEnabled = enabled
}

// Options configures the sandbox execution.
type Options struct {
	CWD       string
	Args      []string
	RunAsUID  int      // unused on Linux (namespace-based isolation instead)
	ExtraEnv  []string // additional env vars (e.g. cert trust vars)
	FilterEnv []string // env var names to remove from inherited environment
	Trace     bool     // unused on Linux (overlay is transparent)
}

// Run executes a command inside a mount-namespace sandbox.
// The entire filesystem is overlayed as read-only with copy-on-write;
// only the CWD is bind-mounted read-write.
func Run(cwd string, args []string) error {
	return RunWithOptions(Options{CWD: cwd, Args: args})
}

// RunWithOptions executes a command inside a mount-namespace sandbox
// with the given options.
func RunWithOptions(opts Options) error {
	cwd, err := filepath.Abs(opts.CWD)
	if err != nil {
		return err
	}

	exe, err := os.Executable()
	if err != nil {
		return err
	}

	// Re-exec boxit as __sandbox-child inside a new user+mount namespace.
	// The child sets up the overlay root and execs the user's command.
	childArgs := []string{"__sandbox-child", cwd, "--"}
	childArgs = append(childArgs, opts.Args...)

	cmd := exec.Command(exe, childArgs...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS,
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getuid(), Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getgid(), Size: 1},
		},
	}
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Dir = cwd

	if len(opts.ExtraEnv) > 0 || len(opts.FilterEnv) > 0 {
		env := os.Environ()
		if len(opts.FilterEnv) > 0 {
			filtered := env[:0:0]
			for _, e := range env {
				keep := true
				for _, name := range opts.FilterEnv {
					if strings.HasPrefix(e, name+"=") {
						keep = false
						break
					}
				}
				if keep {
					filtered = append(filtered, e)
				}
			}
			env = filtered
		}
		cmd.Env = append(env, opts.ExtraEnv...)
	}

	return cmd.Run()
}
