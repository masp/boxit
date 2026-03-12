//go:build darwin || linux

package proxy

import (
	"fmt"
	"os"
	"path/filepath"
)

// BuildCertBundle creates a combined cert bundle by concatenating the system
// CA certificates with the proxy CA certificate. Returns the path to
// the combined bundle file.
func BuildCertBundle(confDir, tmpDir string) (string, error) {
	systemCerts, err := os.ReadFile(systemCertBundlePath())
	if err != nil {
		return "", fmt.Errorf("proxy: read system certs: %w", err)
	}

	caCert := filepath.Join(confDir, "boxit-ca-cert.pem")
	caCerts, err := os.ReadFile(caCert)
	if err != nil {
		return "", fmt.Errorf("proxy: read CA cert: %w", err)
	}

	bundlePath := filepath.Join(tmpDir, "boxit-ca-bundle.pem")
	combined := append(systemCerts, '\n')
	combined = append(combined, caCerts...)

	if err := os.WriteFile(bundlePath, combined, 0644); err != nil {
		return "", fmt.Errorf("proxy: write cert bundle: %w", err)
	}

	return bundlePath, nil
}

// CertEnvVars returns environment variables that configure common tools
// to trust the combined cert bundle containing system CAs + boxit proxy CA.
//
// Only sets env vars that are additive or scoped to specific tools.
// We do NOT set SSL_CERT_FILE or REQUESTS_CA_BUNDLE because they replace
// the system CA store for ALL tools, breaking TLS for tools that bypass
// the proxy (e.g. Rust binaries like Codex). For those tools, run
// "boxit trust" to install the CA in the system keychain instead.
func CertEnvVars(bundlePath string) []string {
	return []string{
		"NODE_EXTRA_CA_CERTS=" + bundlePath, // additive for Node.js/Bun
		"GIT_SSL_CAINFO=" + bundlePath,      // git only
	}
}
