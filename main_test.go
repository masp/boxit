//go:build darwin

package main

import (
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

func TestNoArgs(t *testing.T) {
	cmd := exec.Command(boxitBin)
	cmd.Dir = t.TempDir()
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected non-zero exit code")
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		if exitErr.ExitCode() != 1 {
			t.Fatalf("expected exit code 1, got %d", exitErr.ExitCode())
		}
	}
	if !strings.Contains(string(out), "Usage") {
		t.Fatalf("expected 'Usage' in stderr, got: %s", out)
	}
}

func TestEchoPassthrough(t *testing.T) {
	cmd := exec.Command(boxitBin, "echo", "hello")
	cmd.Dir = t.TempDir()
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(out) != "hello\n" {
		t.Fatalf("expected %q, got %q", "hello\n", string(out))
	}
}

func TestExitCodePassthrough(t *testing.T) {
	cmd := exec.Command(boxitBin, "sh", "-c", "exit 42")
	cmd.Dir = t.TempDir()
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected non-zero exit code")
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected ExitError, got %T", err)
	}
	if exitErr.ExitCode() != 42 {
		t.Fatalf("expected exit code 42, got %d", exitErr.ExitCode())
	}
}

func TestWriteCWDAllowed(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "testfile")
	cmd := exec.Command(boxitBin, "touch", target)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expected write in CWD to succeed: %v\n%s", err, out)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("file should exist: %v", err)
	}
}

func TestWriteOutsideCWDBlocked(t *testing.T) {
	cwd := t.TempDir()

	// Use a path under HOME, which is outside CWD, /private/tmp, and /private/var/folders
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("failed to get home dir: %v", err)
	}
	target := filepath.Join(home, "boxit-sandbox-test-blocked")
	defer os.Remove(target) // clean up in case sandbox fails to block

	cmd := exec.Command(boxitBin, "touch", target)
	cmd.Dir = cwd
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected write outside CWD to be blocked")
	}
	if !strings.Contains(string(out), "Operation not permitted") {
		t.Fatalf("expected 'Operation not permitted' in output, got: %s", out)
	}
}

func TestWriteTmpAllowed(t *testing.T) {
	tmpFile := "/tmp/boxit-test-" + filepath.Base(t.TempDir())
	cmd := exec.Command(boxitBin, "sh", "-c", "touch "+tmpFile+" && rm "+tmpFile)
	cmd.Dir = t.TempDir()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expected write to /tmp to succeed: %v\n%s", err, out)
	}
}

func TestSSHBlocked(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("ssh not found")
	}
	cmd := exec.Command(boxitBin, "ssh", "-o", "ConnectTimeout=2", "-o", "StrictHostKeyChecking=no", "nobody@example.com")
	cmd.Dir = t.TempDir()
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected SSH connection to be blocked")
	}
}

func TestHTTPSAllowed(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not found")
	}
	cmd := exec.Command(boxitBin, "curl", "-sf", "https://example.com")
	cmd.Dir = t.TempDir()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expected HTTPS to be allowed: %v\n%s", err, out)
	}
}

// --- Proxy mode integration tests (require root) ---

func skipUnlessProxyCapable(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("proxy tests require root (run with sudo)")
	}
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not found")
	}
}

func TestProxyBlocksPOST(t *testing.T) {
	skipUnlessProxyCapable(t)
	cmd := exec.Command(boxitBin, "curl", "-sf", "-X", "POST", "https://httpbin.org/post")
	cmd.Dir = t.TempDir()
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected POST to be blocked by default profile")
	}
	if !strings.Contains(string(out), "403") && !strings.Contains(string(out), "not allowed") {
		t.Logf("output: %s", out)
	}
}

func TestProxyAllowsGET(t *testing.T) {
	skipUnlessProxyCapable(t)
	cmd := exec.Command(boxitBin, "curl", "-sf", "https://example.com")
	cmd.Dir = t.TempDir()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expected GET to be allowed: %v\n%s", err, out)
	}
}
