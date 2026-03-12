//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var boxitBin string

func TestMain(m *testing.M) {
	tmp, err := os.MkdirTemp("", "boxit-test-build-")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tmp)

	boxitBin = filepath.Join(tmp, "boxit")
	out, err := exec.Command("go", "build", "-o", boxitBin, ".").CombinedOutput()
	if err != nil {
		panic("failed to build boxit: " + string(out))
	}

	os.Exit(m.Run())
}

func skipUnlessLinuxDeps(t *testing.T) {
	t.Helper()
	for _, bin := range []string{"slirp4netns", "iptables"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not found in PATH", bin)
		}
	}
}

func skipUnlessLinuxCurl(t *testing.T) {
	t.Helper()
	skipUnlessLinuxDeps(t)
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not found in PATH")
	}
}

// --- Basic sandbox tests ---

func TestLinuxEchoPassthrough(t *testing.T) {
	skipUnlessLinuxDeps(t)
	cmd := exec.Command(boxitBin, "echo", "hello")
	cmd.Dir = t.TempDir()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("unexpected error: %v\n%s", err, out)
	}
	if strings.TrimSpace(string(out)) != "hello" {
		t.Fatalf("expected 'hello', got %q", string(out))
	}
}

func TestLinuxExitCodePassthrough(t *testing.T) {
	skipUnlessLinuxDeps(t)
	cmd := exec.Command(boxitBin, "sh", "-c", "exit 42")
	cmd.Dir = t.TempDir()
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected non-zero exit code")
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected ExitError, got %T: %v", err, err)
	}
	if exitErr.ExitCode() != 42 {
		t.Fatalf("expected exit code 42, got %d", exitErr.ExitCode())
	}
}

// --- Mount namespace / filesystem isolation tests ---

func TestLinuxWriteCWDAllowed(t *testing.T) {
	skipUnlessLinuxDeps(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "testfile")
	cmd := exec.Command(boxitBin, "touch", target)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("write in CWD should succeed: %v\n%s", err, out)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("file should exist on host after sandbox exits: %v", err)
	}
}

func TestLinuxWriteCWDPersists(t *testing.T) {
	skipUnlessLinuxDeps(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "persisted")
	cmd := exec.Command(boxitBin, "sh", "-c", fmt.Sprintf("echo persistent > %s", target))
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("write in CWD should succeed: %v\n%s", err, out)
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("file should be readable on host: %v", err)
	}
	if strings.TrimSpace(string(data)) != "persistent" {
		t.Fatalf("expected 'persistent', got %q", string(data))
	}
}

func TestLinuxWriteOutsideCWDNotPersisted(t *testing.T) {
	skipUnlessLinuxDeps(t)
	cwd := t.TempDir()

	// Create a marker file in the home directory. Home is on the root
	// filesystem overlay (not CWD, not /tmp), so writes from inside the
	// sandbox go to the COW tmpfs upper layer and are discarded on exit.
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(home, ".boxit-test-marker")
	if err := os.WriteFile(marker, []byte("original"), 0644); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(marker)

	// Try to overwrite from inside the sandbox.
	// The write may succeed (COW overlay) or fail (readonly bind mount) —
	// either way the host file must remain unchanged.
	cmd := exec.Command(boxitBin, "sh", "-c",
		fmt.Sprintf("echo modified > %s 2>/dev/null; exit 0", marker))
	cmd.Dir = cwd
	cmd.CombinedOutput()

	data, err := os.ReadFile(marker)
	if err != nil {
		t.Fatalf("marker should still exist on host: %v", err)
	}
	if strings.TrimSpace(string(data)) != "original" {
		t.Fatalf("file outside CWD was modified on host: got %q, want 'original'", string(data))
	}
}

func TestLinuxReadOutsideCWD(t *testing.T) {
	skipUnlessLinuxDeps(t)
	cwd := t.TempDir()

	// /etc/hostname exists on most Linux systems and inside Docker containers.
	cmd := exec.Command(boxitBin, "cat", "/etc/hostname")
	cmd.Dir = cwd
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("reads outside CWD should work via overlay lower layer: %v\n%s", err, out)
	}
	if len(strings.TrimSpace(string(out))) == 0 {
		t.Fatal("expected non-empty hostname")
	}
}

func TestLinuxWriteTmpAllowed(t *testing.T) {
	skipUnlessLinuxDeps(t)
	cwd := t.TempDir()
	cmd := exec.Command(boxitBin, "sh", "-c",
		"touch /tmp/boxit-test-tmp && rm /tmp/boxit-test-tmp")
	cmd.Dir = cwd
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("write to /tmp should succeed (sandbox tmpfs): %v\n%s", err, out)
	}
}

// --- Network namespace + proxy tests ---

func TestLinuxProxyBlocksPOST(t *testing.T) {
	skipUnlessLinuxCurl(t)
	cmd := exec.Command(boxitBin, "curl", "-sf", "-X", "POST", "https://httpbin.org/post")
	cmd.Dir = t.TempDir()
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("POST should be blocked by default profile")
	}
	// Expect a 403 or a connection-refused style error from the proxy
	_ = out
}

func TestLinuxProxyAllowsGET(t *testing.T) {
	skipUnlessLinuxCurl(t)
	cmd := exec.Command(boxitBin, "curl", "-sf", "https://example.com")
	cmd.Dir = t.TempDir()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("GET should be allowed by default profile: %v\n%s", err, out)
	}
}

func TestLinuxSSHBlocked(t *testing.T) {
	skipUnlessLinuxDeps(t)
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("ssh not found in PATH")
	}
	cmd := exec.Command(boxitBin, "ssh",
		"-o", "ConnectTimeout=3",
		"-o", "StrictHostKeyChecking=no",
		"nobody@example.com")
	cmd.Dir = t.TempDir()
	err := cmd.Run()
	if err == nil {
		t.Fatal("SSH connection should be blocked by iptables")
	}
}
