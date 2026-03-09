//go:build darwin

package main

import (
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
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

	// Make sure we kill any test-spawned daemons after the run.
	defer func() {
		// Use pkill to stop any background daemons we might have started
		exec.Command("pkill", "-f", "boxit daemon").Run()
	}()

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

func TestDaemonAllocation(t *testing.T) {
	skipUnlessProxyCapable(t)

	// Ensure no previous daemon is running
	exec.Command("pkill", "-f", "boxit daemon").Run()
	os.Remove("/var/run/boxit_daemon.sock")
	time.Sleep(100 * time.Millisecond) // Give the OS a moment to clean up

	// Start the daemon in the background
	cmd := exec.Command(boxitBin, "daemon")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true, // Run in a new session so it doesn't get killed with the test process immediately
	}
	err := cmd.Start()
	if err != nil {
		t.Fatalf("failed to start daemon: %v", err)
	}

	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
		os.Remove("/var/run/boxit_daemon.sock")
	}()

	// Wait for the socket to appear
	var conn net.Conn
	for i := 0; i < 20; i++ {
		conn, err = net.Dial("unix", "/var/run/boxit_daemon.sock")
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("daemon failed to create socket: %v", err)
	}
	defer conn.Close()

	// Ask for an allocation
	_, err = conn.Write([]byte("ALLOC\n"))
	if err != nil {
		t.Fatalf("failed to write to daemon: %v", err)
	}

	// Read response
	var rep struct {
		Username string
		UID      int
		Error    string
	}
	if err := json.NewDecoder(conn).Decode(&rep); err != nil {
		t.Fatalf("failed to read response from daemon: %v", err)
	}

	if rep.Error != "" {
		t.Fatalf("daemon returned error: %s", rep.Error)
	}

	if !strings.HasPrefix(rep.Username, "_boxit_") {
		t.Errorf("unexpected username format: %s", rep.Username)
	}
	if rep.UID < 400 || rep.UID > 499 {
		t.Errorf("unexpected UID range: %d", rep.UID)
	}

	// The user should now exist
	out, err := exec.Command("id", "-u", rep.Username).CombinedOutput()
	if err != nil {
		t.Errorf("user %s does not exist: %s", rep.Username, out)
	}

	// Close connection; daemon should automatically delete the user
	conn.Close()

	// Poll for the daemon to clean up the user (dscl can be slow)
	var deleted bool
	for i := 0; i < 30; i++ {
		time.Sleep(200 * time.Millisecond)
		if _, err := exec.Command("id", "-u", rep.Username).CombinedOutput(); err != nil {
			deleted = true
			break
		}
	}
	if !deleted {
		t.Errorf("expected user %s to be deleted, but it still exists", rep.Username)
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

// --- Explicit proxy tests (non-root, uses http_proxy/https_proxy env vars) ---

func skipUnlessCurl(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not found")
	}
}

func TestExplicitProxyBlocksPOST(t *testing.T) {
	skipUnlessCurl(t)
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

func TestExplicitProxyAllowsGET(t *testing.T) {
	skipUnlessCurl(t)
	cmd := exec.Command(boxitBin, "curl", "-sf", "https://example.com")
	cmd.Dir = t.TempDir()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expected GET to be allowed: %v\n%s", err, out)
	}
}

// --- Transparent proxy integration tests (require root for pf + temp user) ---

func skipUnlessRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root (run with sudo)")
	}
}

func skipUnlessProxyCapable(t *testing.T) {
	t.Helper()
	skipUnlessRoot(t)
	skipUnlessCurl(t)
}

func TestTransparentProxyBlocksPOST(t *testing.T) {
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

func TestTransparentProxyAllowsGET(t *testing.T) {
	skipUnlessProxyCapable(t)
	cmd := exec.Command(boxitBin, "curl", "-sf", "https://example.com")
	cmd.Dir = t.TempDir()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expected GET to be allowed: %v\n%s", err, out)
	}
}
