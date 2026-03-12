//go:build darwin || linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"github.com/masp/boxit/proxy"
)

func runTrust() error {
	// Ensure the CA exists (generate if needed)
	caDir, err := proxy.CADir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(caDir, 0700); err != nil {
		return fmt.Errorf("create CA dir: %w", err)
	}

	// Generate CA if it doesn't exist yet by creating a temp confdir
	certPath, err := proxy.CACertPath()
	if err != nil {
		return err
	}
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		tmpDir, err := os.MkdirTemp("", "boxit-trust-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(tmpDir)
		if _, err := proxy.NewCA(tmpDir); err != nil {
			return fmt.Errorf("generate CA: %w", err)
		}
		fmt.Fprintln(os.Stderr, "boxit: generated new CA certificate")
	}

	fmt.Fprintf(os.Stderr, "boxit: CA certificate at %s\n", certPath)

	switch runtime.GOOS {
	case "darwin":
		return trustDarwin(certPath)
	case "linux":
		return trustLinux(certPath)
	default:
		return fmt.Errorf("trust is not supported on %s", runtime.GOOS)
	}
}

func trustDarwin(certPath string) error {
	fmt.Fprintln(os.Stderr, "boxit: installing CA certificate in system keychain (requires sudo)...")
	cmd := exec.Command("sudo", "security", "add-trusted-cert",
		"-d", "-r", "trustRoot",
		"-k", "/Library/Keychains/System.keychain",
		certPath,
	)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to install CA certificate: %w", err)
	}
	fmt.Fprintln(os.Stderr, "boxit: CA certificate installed successfully")
	fmt.Fprintln(os.Stderr, "boxit: all HTTPS traffic through boxit will now be trusted system-wide")
	return nil
}

func trustLinux(certPath string) error {
	fmt.Fprintln(os.Stderr, "boxit: to trust the CA certificate on Linux, copy it to your system CA store:")
	fmt.Fprintf(os.Stderr, "\n  sudo cp %s /usr/local/share/ca-certificates/boxit-ca.crt\n", certPath)
	fmt.Fprintln(os.Stderr, "  sudo update-ca-certificates")
	fmt.Fprintln(os.Stderr)
	return nil
}
