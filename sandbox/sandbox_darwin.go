//go:build darwin

package sandbox

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

var traceEnabled bool

// SetTrace enables sandbox tracing globally. When enabled, sandbox deny
// decisions are captured from the macOS unified log and printed to stderr.
func SetTrace(enabled bool) {
	traceEnabled = enabled
}

// sandboxProfile returns the SBPL sandbox profile.
func sandboxProfile() string {
	return `(version 1)
(allow default)

;; Deny all file writes
(deny file-write*)

;; Allow writes to CWD (parameterized)
(allow file-write* (subpath (param "CWD")))

;; Allow writes to the sandboxed command's config directory (e.g. ~/.claude)
(allow file-write* (subpath (param "CONFIG_DIR")))

;; Allow writes to home config files (e.g. ~/.claude.json, ~/.claude.json.lock, ~/.claude.json.tmp.*)
(allow file-write* (regex (param "CONFIG_FILE_REGEX")))

;; Allow writes to system temp dirs (symlink-resolved paths)
(allow file-write*
    (subpath "/private/tmp")
    (subpath "/private/var/folders")
)

;; Allow writes to device nodes (/dev/null, /dev/tty, /dev/fd for process substitution)
(allow file-write* (subpath "/dev"))

;; Allow writes to system Keychains and security databases so trustd can
;; evaluate TLS certificates (without this, all HTTPS connections hang)
(allow file-write* (subpath "/private/var/db"))

;; Allow writes to user Library for system frameworks (HTTPStorages, Biome, etc.)
(allow file-write* (subpath (param "HOME_LIBRARY")))

;; Allow IPC: mach service lookups needed by system frameworks
(allow mach-lookup)

;; Allow IPC: POSIX shared memory (ContextStoreAgent, etc.)
(allow ipc-posix-shm-write-create)
(allow ipc-posix-shm-read-data)

;; Allow process info queries
(allow process-info-pidinfo)

;; Allow execution of setuid/setgid binaries
(allow process-exec*)

;; Allow CFPreferences file extensions and user preference reads
(allow file-issue-extension)
(allow user-preference-read)

;; Allow system fsctl operations
(allow system-fsctl)

;; Allow IOKit user client access (Apple KeyStore, etc.)
(allow iokit-open-user-client)

;; Explicitly allow all network operations (allow default may not cover these on newer macOS)
(allow network-outbound)
(allow network-inbound)
(allow network-bind)
(allow system-socket)

;; Allow writes to dot files and dot directories in the user's home directory
;; (e.g. ~/.bashrc, ~/.config/*, ~/.ssh/known_hosts)
(allow file-write* (regex (param "HOME_DOT_REGEX")))

;; Block file deletions outside of the working directory, home dot dirs, and system temp dirs
(deny file-write-unlink
    (require-all
        (require-not (subpath (param "CWD")))
        (require-not (regex (param "HOME_DOT_REGEX")))
        (require-not (subpath "/private/tmp"))
        (require-not (subpath "/private/var/folders"))
    )
)

;; Block SSH (port 22) — prevents git push over SSH, allows HTTPS clone/fetch
(deny network-outbound (remote tcp "*:22"))
`
}

// Options configures the sandbox execution.
type Options struct {
	CWD       string
	Args      []string
	RunAsUID  int      // 0 = current user (no proxy mode)
	ExtraEnv  []string // additional env vars (e.g. cert trust vars)
	FilterEnv []string // env var names to remove from inherited environment
	Trace     bool     // log all sandbox decisions to a temp file
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

	configDir := configDirForCommand(opts.Args[0])
	homeLibrary := homeLibraryDir()
	// Regex to match config files like ~/.claude.json, ~/.claude.json.lock, ~/.claude.json.tmp.*
	configFileRegex := "^" + regexQuotePath(configDir) + "\\.json"
	// Regex to match any dot file or dot directory in $HOME (e.g. ~/.bashrc, ~/.config/*)
	homeDotRegex := homeDotFileRegex()

	prof := sandboxProfile()
	slog.Debug("sandbox: setup", "cwd", cwd, "configDir", configDir, "homeLibrary", homeLibrary, "args", opts.Args)

	sandboxArgs := []string{
		"-D", "CWD=" + cwd,
		"-D", "CONFIG_DIR=" + configDir,
		"-D", "CONFIG_FILE_REGEX=" + configFileRegex,
		"-D", "HOME_LIBRARY=" + homeLibrary,
		"-D", "HOME_DOT_REGEX=" + homeDotRegex,
		"-p", prof,
	}
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

	if (len(opts.ExtraEnv) > 0 || len(opts.FilterEnv) > 0) && opts.RunAsUID == 0 {
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

	tracing := opts.Trace || traceEnabled
	var traceStart time.Time
	if tracing {
		fmt.Fprintln(os.Stderr, "boxit: tracing sandbox denials...")
		traceStart = time.Now()
	}

	slog.Debug("sandbox: exec", "path", cmd.Path, "args", cmd.Args)
	if err := cmd.Start(); err != nil {
		return err
	}
	slog.Debug("sandbox: child started", "pid", cmd.Process.Pid)

	// Let signals pass through to the child naturally (same process group).
	// SIGTERM is caught to ensure we can clean up if killed externally.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM)
	go func() {
		<-sigCh
		slog.Debug("sandbox: SIGTERM received, killing child", "pid", cmd.Process.Pid)
		cmd.Process.Kill()
	}()

	err = cmd.Wait()
	signal.Stop(sigCh)
	slog.Debug("sandbox: child exited", "pid", cmd.Process.Pid, "err", err)

	if tracing {
		showTraceDenials(traceStart)
	}

	return err
}

// configDirForCommand returns the config directory for a command.
// Convention: ~/.{command_name} (e.g. ~/.claude for the "claude" command).
func configDirForCommand(command string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "/tmp"
	}
	base := filepath.Base(command)
	return filepath.Join(home, "."+base)
}

// regexQuotePath escapes special regex characters in a file path.
func regexQuotePath(path string) string {
	var b strings.Builder
	for _, c := range path {
		switch c {
		case '.', '\\', '(', ')', '[', ']', '{', '}', '+', '*', '?', '|', '^', '$':
			b.WriteByte('\\')
		}
		b.WriteRune(c)
	}
	return b.String()
}

// homeDotFileRegex returns a regex matching any dot file or dot directory
// under the user's home directory (e.g. ~/.bashrc, ~/.config/anything).
func homeDotFileRegex() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "/tmp"
	}
	return "^" + regexQuotePath(home) + "/\\."
}

// homeLibraryDir returns ~/Library for the current user.
func homeLibraryDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "/tmp"
	}
	return filepath.Join(home, "Library")
}

// showTraceDenials queries the macOS unified log for sandbox deny events
// that occurred since startTime and prints them to stderr.
func showTraceDenials(startTime time.Time) {
	start := startTime.Format("2006-01-02 15:04:05")
	out, err := exec.Command("/usr/bin/log", "show",
		"--start", start,
		"--predicate", `eventMessage CONTAINS "deny" AND sender == "Sandbox"`,
		"--style", "compact",
	).Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "boxit: trace: log show failed: %v\n", err)
		return
	}

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	var denies []string
	seen := make(map[string]bool)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Filtering") || strings.HasPrefix(line, "Timestamp") {
			continue
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		// Extract the deny description (e.g. "deny(1) file-write-create /usr/local/test")
		if idx := strings.Index(line, "deny("); idx >= 0 {
			desc := line[idx:]
			if seen[desc] {
				continue
			}
			seen[desc] = true
			denies = append(denies, desc)
		}
	}

	if len(denies) == 0 {
		fmt.Fprintln(os.Stderr, "boxit: trace: no sandbox denials recorded")
	} else {
		fmt.Fprintf(os.Stderr, "boxit: trace: %d sandbox denial(s):\n", len(denies))
		for _, d := range denies {
			fmt.Fprintf(os.Stderr, "  %s\n", d)
		}
	}
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
