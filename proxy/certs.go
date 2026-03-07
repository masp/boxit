//go:build darwin

package proxy

import (
	"fmt"
	"os"
	"path/filepath"
)

const systemCertBundle = "/etc/ssl/cert.pem"

// BuildCertBundle creates a combined cert bundle by concatenating the system
// CA certificates with the proxy CA certificate. Returns the path to
// the combined bundle file.
func BuildCertBundle(confDir, tmpDir string) (string, error) {
	systemCerts, err := os.ReadFile(systemCertBundle)
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
// to trust the combined cert bundle.
func CertEnvVars(bundlePath string) []string {
	return []string{
		"SSL_CERT_FILE=" + bundlePath,
		"REQUESTS_CA_BUNDLE=" + bundlePath,
		"NODE_EXTRA_CA_CERTS=" + bundlePath,
		"GIT_SSL_CAINFO=" + bundlePath,
	}
}
