//go:build darwin

package netfilter

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// PFAnchor manages a named pf anchor that redirects HTTP/HTTPS traffic
// from a specific UID to a local proxy port.
type PFAnchor struct {
	Name string
}

// Install creates pf rules that redirect HTTP (80) and HTTPS (443) traffic
// from the given UID to the local proxy port. It also enables pf if needed.
func (a *PFAnchor) Install(uid, proxyPort int) error {
	// Ensure the main pf config references our anchors so they are evaluated.
	if err := ensureAnchorRefs(); err != nil {
		return fmt.Errorf("netfilter: %w", err)
	}

	rules := fmt.Sprintf(
		"rdr pass on lo0 proto tcp from any to !127.0.0.0/8 port {80, 443} -> 127.0.0.1 port %d\n"+
			"pass out route-to lo0 proto tcp from any to any port {80, 443} user %d\n",
		proxyPort, uid,
	)

	tmpFile, err := os.CreateTemp("", "boxit-pf-*.conf")
	if err != nil {
		return fmt.Errorf("netfilter: create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(rules); err != nil {
		tmpFile.Close()
		return fmt.Errorf("netfilter: write rules: %w", err)
	}
	tmpFile.Close()

	// Load rules into our anchor
	anchorPath := anchorFor(a.Name)
	if out, err := exec.Command("pfctl", "-a", anchorPath, "-f", tmpFile.Name()).CombinedOutput(); err != nil {
		return fmt.Errorf("netfilter: load anchor: %s: %w", strings.TrimSpace(string(out)), err)
	}

	// Enable pf (idempotent — returns success if already enabled)
	exec.Command("pfctl", "-e").Run()

	return nil
}

// Cleanup flushes all rules in the anchor and restores the original pf config.
func (a *PFAnchor) Cleanup() error {
	anchorPath := anchorFor(a.Name)
	if out, err := exec.Command("pfctl", "-a", anchorPath, "-F", "all").CombinedOutput(); err != nil {
		return fmt.Errorf("netfilter: flush anchor: %s: %w", strings.TrimSpace(string(out)), err)
	}
	// Restore original pf config (removes our anchor references)
	exec.Command("pfctl", "-f", "/etc/pf.conf").Run()
	return nil
}

// anchorFor returns a pf-safe anchor path for the given name.
// macOS pfctl rejects anchor names starting with '_', so we strip it.
func anchorFor(name string) string {
	return "com.boxit/" + strings.TrimLeft(name, "_")
}

// ensureAnchorRefs ensures the main pf configuration includes references to
// our rdr-anchor and anchor so that rules loaded into our anchor are evaluated.
func ensureAnchorRefs() error {
	existing, err := os.ReadFile("/etc/pf.conf")
	if err != nil {
		existing = []byte{}
	}

	content := string(existing)
	if strings.Contains(content, "com.boxit") {
		// Already referenced, just reload to ensure it's active.
		tmpFile, err := os.CreateTemp("", "boxit-pf-main-*.conf")
		if err != nil {
			return err
		}
		defer os.Remove(tmpFile.Name())
		os.WriteFile(tmpFile.Name(), existing, 0600)
		exec.Command("pfctl", "-f", tmpFile.Name()).CombinedOutput()
		return nil
	}

	// Insert our anchor references in the correct positions:
	// - rdr-anchor after the last existing rdr-anchor line (NAT section)
	// - anchor after the last existing anchor line (filter section), but before "load anchor"
	lines := strings.Split(content, "\n")
	var result []string

	lastRdrAnchor := -1
	lastAnchor := -1
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "rdr-anchor") {
			lastRdrAnchor = i
		}
		if strings.HasPrefix(trimmed, "anchor") && !strings.HasPrefix(trimmed, "load anchor") {
			lastAnchor = i
		}
	}

	for i, line := range lines {
		result = append(result, line)
		if i == lastRdrAnchor {
			result = append(result, `rdr-anchor "com.boxit/*"`)
		}
		if i == lastAnchor {
			result = append(result, `anchor "com.boxit/*"`)
		}
	}

	// If no existing anchors found, append at the end
	if lastRdrAnchor == -1 {
		result = append(result, `rdr-anchor "com.boxit/*"`)
	}
	if lastAnchor == -1 {
		result = append(result, `anchor "com.boxit/*"`)
	}

	augmented := strings.Join(result, "\n")

	tmpFile, err := os.CreateTemp("", "boxit-pf-main-*.conf")
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile.Name())

	if err := os.WriteFile(tmpFile.Name(), []byte(augmented), 0600); err != nil {
		return err
	}

	if out, err := exec.Command("pfctl", "-f", tmpFile.Name()).CombinedOutput(); err != nil {
		return fmt.Errorf("load main pf config: %s: %w", strings.TrimSpace(string(out)), err)
	}

	return nil
}
