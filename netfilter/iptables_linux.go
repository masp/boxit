//go:build linux

package netfilter

import (
	"fmt"
	"os/exec"
	"strings"
)

const slirp4netnsGateway = "10.0.2.2"

// SetupIPTables configures iptables rules inside a network namespace to:
//   - Redirect HTTP (80) and HTTPS (443) traffic to the proxy via the slirp4netns gateway
//   - Block SSH (port 22)
func SetupIPTables(proxyPort int) error {
	dest := fmt.Sprintf("%s:%d", slirp4netnsGateway, proxyPort)

	rules := [][]string{
		// Redirect HTTP to proxy
		{"iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "--dport", "80",
			"-j", "DNAT", "--to-destination", dest},
		// Redirect HTTPS to proxy
		{"iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "--dport", "443",
			"-j", "DNAT", "--to-destination", dest},
		// Block SSH
		{"iptables", "-A", "OUTPUT", "-p", "tcp", "--dport", "22", "-j", "DROP"},
	}

	for _, args := range rules {
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("netfilter: %s: %s: %w",
				strings.Join(args, " "), strings.TrimSpace(string(out)), err)
		}
	}

	return nil
}
