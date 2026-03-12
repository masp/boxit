//go:build linux

package proxy

import "os"

func systemCertBundlePath() string {
	// Check common Linux CA bundle locations
	paths := []string{
		"/etc/ssl/certs/ca-certificates.crt", // Debian/Ubuntu
		"/etc/pki/tls/certs/ca-bundle.crt",   // RHEL/CentOS/Fedora
		"/etc/ssl/ca-bundle.pem",              // openSUSE
		"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // CentOS 7+
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return paths[0] // default; will produce a clear error in BuildCertBundle
}
