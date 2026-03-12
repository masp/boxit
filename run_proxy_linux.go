//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/masp/boxit/netfilter"
	"github.com/masp/boxit/profile"
	"github.com/masp/boxit/proxy"
	"github.com/masp/boxit/sandbox"
)

// runWithProxy runs the command inside a rootless network+mount namespace with
// slirp4netns for connectivity and iptables for transparent proxy redirection.
func runWithProxy(cwd string, args []string, prof *profile.Profile) error {
	// Cleanup stack: functions run in reverse order on exit
	var cleanups []func() error
	cleanup := func() {
		for i := len(cleanups) - 1; i >= 0; i-- {
			if err := cleanups[i](); err != nil {
				fmt.Fprintf(os.Stderr, "boxit: cleanup: %v\n", err)
			}
		}
	}

	// Handle signals for cleanup
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cleanup()
		os.Exit(130)
	}()

	// Check dependencies
	for _, bin := range []string{"slirp4netns", "iptables"} {
		if _, err := exec.LookPath(bin); err != nil {
			return fmt.Errorf("%s is required for Linux sandboxing but not found in PATH", bin)
		}
	}

	// 1. Create temp dir for cert bundle inside the CWD so it survives the
	// mount namespace overlay (which replaces /tmp with a fresh tmpfs).
	tmpDir, err := os.MkdirTemp(cwd, ".boxit-run-")
	if err != nil {
		return err
	}
	cleanups = append(cleanups, func() error { return os.RemoveAll(tmpDir) })

	// 2. Start proxy on the host
	p, err := proxy.Start(prof)
	if err != nil {
		cleanup()
		return err
	}
	cleanups = append(cleanups, p.Stop)

	// 3. Build cert bundle
	certBundle, err := proxy.BuildCertBundle(p.ConfDir, tmpDir)
	if err != nil {
		cleanup()
		return err
	}

	// 4. Create sync pipe (parent → child: "networking is ready")
	syncR, syncW, err := os.Pipe()
	if err != nil {
		cleanup()
		return fmt.Errorf("create sync pipe: %w", err)
	}

	// 5. Create ready pipe for slirp4netns
	readyR, readyW, err := os.Pipe()
	if err != nil {
		syncR.Close()
		syncW.Close()
		cleanup()
		return fmt.Errorf("create ready pipe: %w", err)
	}

	// 6. Re-exec boxit in a new user+net+mount namespace
	exe, err := os.Executable()
	if err != nil {
		syncR.Close()
		syncW.Close()
		readyR.Close()
		readyW.Close()
		cleanup()
		return fmt.Errorf("find executable: %w", err)
	}

	childArgs := []string{"__netns-child", strconv.Itoa(p.Port), cwd, "--"}
	childArgs = append(childArgs, args...)

	cmd := exec.Command(exe, childArgs...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET | syscall.CLONE_NEWNS,
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getuid(), Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getgid(), Size: 1},
		},
	}
	cmd.ExtraFiles = []*os.File{syncR} // fd 3 in child
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Dir = cwd
	cmd.Env = append(os.Environ(), proxy.CertEnvVars(certBundle)...)

	if err := cmd.Start(); err != nil {
		syncR.Close()
		syncW.Close()
		readyR.Close()
		readyW.Close()
		cleanup()
		return fmt.Errorf("start namespace child: %w", err)
	}
	syncR.Close()

	// 7. Start slirp4netns to provide network connectivity in the namespace
	slirp := exec.Command("slirp4netns",
		"--configure",
		"--mtu=65520",
		"--ready-fd=3",
		strconv.Itoa(cmd.Process.Pid),
		"tap0",
	)
	slirp.ExtraFiles = []*os.File{readyW} // fd 3 in slirp4netns
	if err := slirp.Start(); err != nil {
		syncW.Close()
		readyR.Close()
		readyW.Close()
		cmd.Process.Kill()
		cmd.Wait()
		cleanup()
		return fmt.Errorf("start slirp4netns: %w", err)
	}
	readyW.Close()

	cleanups = append(cleanups, func() error {
		slirp.Process.Kill()
		slirp.Wait()
		return nil
	})

	// 8. Wait for slirp4netns to signal it has configured the interface
	buf := make([]byte, 1)
	readyR.Read(buf)
	readyR.Close()

	// 9. Signal child that networking is ready
	syncW.Write([]byte("1"))
	syncW.Close()

	// 10. Wait for child to exit
	err = cmd.Wait()
	cleanup()
	return err
}

// runWithExplicitProxy on Linux uses the same namespace-based transparent proxy
// since rootless namespaces work without root privileges.
func runWithExplicitProxy(cwd string, args []string, prof *profile.Profile) error {
	return runWithProxy(cwd, args, prof)
}

// runNetNSChild is the entry point for the child process inside the
// network+mount namespace. It waits for slirp4netns, sets up iptables to
// redirect HTTP/HTTPS to the proxy, configures the overlay filesystem,
// and execs the user's command.
func runNetNSChild(args []string) error {
	// args: <proxyPort> <cwd> -- <cmd> [args...]
	if len(args) < 4 {
		return fmt.Errorf("usage: __netns-child <proxyPort> <cwd> -- <cmd> [args...]")
	}

	proxyPort, err := strconv.Atoi(args[0])
	if err != nil {
		return fmt.Errorf("invalid proxy port: %w", err)
	}

	cwd := args[1]

	// Find -- separator
	sepIdx := -1
	for i, a := range args[2:] {
		if a == "--" {
			sepIdx = i + 2
			break
		}
	}
	if sepIdx == -1 || sepIdx+1 >= len(args) {
		return fmt.Errorf("missing -- separator or command")
	}
	cmdArgs := args[sepIdx+1:]

	// Wait for parent to signal that networking is ready (fd 3)
	syncFd := os.NewFile(3, "sync")
	buf := make([]byte, 1)
	syncFd.Read(buf)
	syncFd.Close()

	// Set up iptables rules (must happen before mount namespace changes
	// so the iptables binary is accessible on the original filesystem)
	if err := netfilter.SetupIPTables(proxyPort); err != nil {
		return err
	}

	// Set up overlay filesystem (COW root, CWD read-write)
	if err := sandbox.SetupMountNamespace(cwd); err != nil {
		return err
	}

	// Exec the user's command (replaces this process)
	cmdPath, err := exec.LookPath(cmdArgs[0])
	if err != nil {
		return err
	}

	return syscall.Exec(cmdPath, cmdArgs, os.Environ())
}

// runSandboxChild is the entry point for the child process inside a
// mount-only namespace (no network namespace, no proxy).
func runSandboxChild(args []string) error {
	// args: <cwd> -- <cmd> [args...]
	if len(args) < 3 {
		return fmt.Errorf("usage: __sandbox-child <cwd> -- <cmd> [args...]")
	}

	cwd := args[0]

	sepIdx := -1
	for i, a := range args[1:] {
		if a == "--" {
			sepIdx = i + 1
			break
		}
	}
	if sepIdx == -1 || sepIdx+1 >= len(args) {
		return fmt.Errorf("missing -- separator or command")
	}
	cmdArgs := args[sepIdx+1:]

	// Set up overlay filesystem (COW root, CWD read-write)
	if err := sandbox.SetupMountNamespace(cwd); err != nil {
		return err
	}

	cmdPath, err := exec.LookPath(cmdArgs[0])
	if err != nil {
		return err
	}

	return syscall.Exec(cmdPath, cmdArgs, os.Environ())
}
