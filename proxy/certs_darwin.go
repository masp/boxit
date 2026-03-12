//go:build darwin

package proxy

func systemCertBundlePath() string {
	return "/etc/ssl/cert.pem"
}
