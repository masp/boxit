//go:build darwin

package main

import (
	"os"
	"os/exec"
	"testing"
)

// TestLinuxViaDocker builds a Docker container with the Linux test
// dependencies (slirp4netns, iptables, curl, ssh) and runs the
// TestLinux* integration tests inside it. This lets you validate the
// full Linux namespace sandbox from a macOS development machine.
//
// Prerequisites: Docker Desktop must be installed and running.
// The container runs with --privileged so CLONE_NEWUSER, CLONE_NEWNET,
// CLONE_NEWNS, overlayfs, iptables, and slirp4netns all work.
func TestLinuxViaDocker(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not found in PATH")
	}

	// Quick smoke-test that the daemon is reachable.
	// "docker info" can return exit 0 even without a server, so use
	// "docker version" which reliably fails when the daemon is down.
	if out, err := exec.Command("docker", "version", "--format", "{{.Server.Version}}").CombinedOutput(); err != nil {
		t.Skipf("docker daemon not running: %s", out)
	}

	// Build the test image
	build := exec.Command("docker", "build",
		"-f", "Dockerfile.test",
		"-t", "boxit-linux-test",
		".")
	build.Stdout = os.Stdout
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("docker build failed: %v", err)
	}

	// Run the Linux integration tests inside the container.
	// --privileged is required for:
	//   - CLONE_NEWUSER + CLONE_NEWNET + CLONE_NEWNS
	//   - overlayfs in user namespaces (kernel 5.11+)
	//   - iptables inside network namespaces
	//   - slirp4netns accessing /proc/<pid>/ns/net
	run := exec.Command("docker", "run", "--rm", "--privileged", "boxit-linux-test")
	run.Stdout = os.Stdout
	run.Stderr = os.Stderr
	if err := run.Run(); err != nil {
		t.Fatalf("Linux tests failed in Docker: %v", err)
	}
}
