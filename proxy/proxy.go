//go:build darwin

package proxy

import (
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/masp/boxit/profile"
)

// Proxy manages the lifecycle of the transparent proxy.
type Proxy struct {
	Port    int
	ConfDir string // contains boxit-ca-cert.pem
	tp      *transparentProxy
	tmpDir  string
}

// Start launches the transparent proxy on a free port.
func Start(prof *profile.Profile) (*Proxy, error) {
	tmpDir, err := os.MkdirTemp("", "boxit-proxy-")
	if err != nil {
		return nil, fmt.Errorf("proxy: create temp dir: %w", err)
	}

	confDir := filepath.Join(tmpDir, "conf")
	if err := os.MkdirAll(confDir, 0700); err != nil {
		os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("proxy: create confdir: %w", err)
	}

	ca, err := NewCA(confDir)
	if err != nil {
		os.RemoveAll(tmpDir)
		return nil, err
	}

	filter := NewFilter(prof)

	port, err := freePort()
	if err != nil {
		os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("proxy: find free port: %w", err)
	}

	tp, err := newTransparentProxy(port, ca, filter)
	if err != nil {
		os.RemoveAll(tmpDir)
		return nil, err
	}

	go tp.serve()

	return &Proxy{
		Port:    port,
		ConfDir: confDir,
		tp:      tp,
		tmpDir:  tmpDir,
	}, nil
}

// Stop shuts down the proxy and cleans up temp files.
func (p *Proxy) Stop() error {
	if p.tp != nil {
		p.tp.stop()
	}
	if p.tmpDir != "" {
		os.RemoveAll(p.tmpDir)
	}
	return nil
}

// ProxyEnvVars returns environment variables that configure tools to use
// the proxy via explicit http_proxy/https_proxy variables.
func ProxyEnvVars(port int) []string {
	proxyURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	return []string{
		"http_proxy=" + proxyURL,
		"https_proxy=" + proxyURL,
		"HTTP_PROXY=" + proxyURL,
		"HTTPS_PROXY=" + proxyURL,
	}
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port, nil
}
