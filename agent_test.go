//go:build darwin || linux

package main

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Agent integration tests verify that popular AI CLI agents can start and
// run prompts under boxit without modifications. Each test is skipped if
// the agent's executable is not found in PATH.
//
// Run all agent tests:
//   go test -run TestAgent -v -timeout 10m
//
// Run just the smoke tests (no API key needed):
//   go test -run TestAgent.*version -v

// skipUnlessAgent skips the test if the given executable is not in PATH.
func skipUnlessAgent(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("%s not installed, skipping", name)
	}
}

// skipUnlessEnv skips the test unless at least one of the given env vars is non-empty.
func skipUnlessEnv(t *testing.T, vars ...string) {
	t.Helper()
	for _, v := range vars {
		if os.Getenv(v) != "" {
			return
		}
	}
	t.Skipf("none of %v set, skipping", vars)
}

// initGitRepo creates a minimal git repo in dir so agents that expect one can start.
func initGitRepo(t *testing.T, dir string) {
	t.Helper()
	for _, args := range [][]string{
		{"git", "init", dir},
		{"git", "-C", dir, "config", "user.email", "test@boxit.dev"},
		{"git", "-C", dir, "config", "user.name", "boxit-test"},
		{"git", "-C", dir, "commit", "--allow-empty", "-m", "init"},
	} {
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("git setup failed (%v): %v\n%s", args, err, out)
		}
	}
}

// runBoxitAgent runs boxit with the given args, a working directory, and a timeout.
func runBoxitAgent(t *testing.T, dir string, timeout time.Duration, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, boxitBin, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("command timed out after %v: boxit %s", timeout, strings.Join(args, " "))
	}
	return string(out), err
}

// ---------- Claude Code ----------

func TestAgentClaude(t *testing.T) {
	skipUnlessAgent(t, "claude")

	t.Run("version", func(t *testing.T) {
		out, err := runBoxitAgent(t, t.TempDir(), 30*time.Second, "claude", "--version")
		if err != nil {
			t.Fatalf("claude --version failed under boxit: %v\n%s", err, out)
		}
		t.Logf("claude %s", strings.TrimSpace(out))
	})

	t.Run("prompt", func(t *testing.T) {
		skipUnlessEnv(t, "ANTHROPIC_API_KEY")
		dir := t.TempDir()
		initGitRepo(t, dir)
		out, err := runBoxitAgent(t, dir, 120*time.Second,
			"claude", "-p", "respond with exactly the text: BOXIT_OK",
			"--output-format", "text", "--max-turns", "1")
		if err != nil {
			t.Fatalf("claude prompt failed under boxit: %v\n%s", err, out)
		}
		if !strings.Contains(out, "BOXIT_OK") {
			t.Errorf("expected BOXIT_OK in output, got:\n%s", out)
		}
	})
}

// ---------- OpenAI Codex ----------

func TestAgentCodex(t *testing.T) {
	skipUnlessAgent(t, "codex")

	t.Run("version", func(t *testing.T) {
		out, err := runBoxitAgent(t, t.TempDir(), 30*time.Second, "codex", "--version")
		if err != nil {
			t.Fatalf("codex --version failed under boxit: %v\n%s", err, out)
		}
		t.Logf("codex %s", strings.TrimSpace(out))
	})

	t.Run("prompt", func(t *testing.T) {
		skipUnlessEnv(t, "OPENAI_API_KEY")
		dir := t.TempDir()
		initGitRepo(t, dir)
		out, err := runBoxitAgent(t, dir, 120*time.Second,
			"codex", "--approval-mode", "full-auto", "-q",
			"respond with exactly the text: BOXIT_OK")
		if err != nil {
			t.Fatalf("codex prompt failed under boxit: %v\n%s", err, out)
		}
		t.Logf("codex output:\n%s", out)
	})
}

// ---------- Aider ----------

func TestAgentAider(t *testing.T) {
	skipUnlessAgent(t, "aider")

	t.Run("version", func(t *testing.T) {
		out, err := runBoxitAgent(t, t.TempDir(), 30*time.Second, "aider", "--version")
		if err != nil {
			t.Fatalf("aider --version failed under boxit: %v\n%s", err, out)
		}
		t.Logf("aider %s", strings.TrimSpace(out))
	})

	t.Run("prompt", func(t *testing.T) {
		skipUnlessEnv(t, "ANTHROPIC_API_KEY", "OPENAI_API_KEY")
		dir := t.TempDir()
		initGitRepo(t, dir)
		out, err := runBoxitAgent(t, dir, 120*time.Second,
			"aider", "--message", "respond with exactly the text: BOXIT_OK",
			"--yes", "--no-auto-commits")
		if err != nil {
			t.Fatalf("aider prompt failed under boxit: %v\n%s", err, out)
		}
		t.Logf("aider output:\n%s", out)
	})
}

// ---------- Kiro ----------

func TestAgentKiro(t *testing.T) {
	skipUnlessAgent(t, "kiro")

	t.Run("version", func(t *testing.T) {
		out, err := runBoxitAgent(t, t.TempDir(), 30*time.Second, "kiro", "--version")
		if err != nil {
			t.Fatalf("kiro --version failed under boxit: %v\n%s", err, out)
		}
		t.Logf("kiro %s", strings.TrimSpace(out))
	})
}
