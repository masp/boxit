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
	rules := fmt.Sprintf(
		"rdr pass on lo0 proto tcp from any to any -> 127.0.0.1 port %d\n"+
			"pass out on en0 route-to lo0 proto tcp from any to any user %d\n",
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
	anchorPath := "com.boxit." + a.Name
	if out, err := exec.Command("pfctl", "-a", anchorPath, "-f", tmpFile.Name()).CombinedOutput(); err != nil {
		return fmt.Errorf("netfilter: load anchor: %s: %w", strings.TrimSpace(string(out)), err)
	}

	// Enable pf (idempotent — returns success if already enabled)
	exec.Command("pfctl", "-e").Run()

	return nil
}

// Cleanup flushes all rules in the anchor.
func (a *PFAnchor) Cleanup() error {
	anchorPath := "com.boxit." + a.Name
	if out, err := exec.Command("pfctl", "-a", anchorPath, "-F", "all").CombinedOutput(); err != nil {
		return fmt.Errorf("netfilter: flush anchor: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}
