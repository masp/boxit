//go:build darwin

package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/masp/boxit/netfilter"
	"github.com/masp/boxit/profile"
	"github.com/masp/boxit/proxy"
	"github.com/masp/boxit/sandbox"
	"github.com/masp/boxit/userutil"
)

func runWithProxy(cwd string, args []string, prof *profile.Profile) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("HTTPS filtering requires elevated privileges. Re-run with sudo")
	}

	// Cleanup stack: functions run in reverse order on exit
	var cleanups []func() error
	cleanup := func() {
		for i := len(cleanups) - 1; i >= 0; i-- {
			if err := cleanups[i](); err != nil {
				fmt.Fprintf(os.Stderr, "boxit: cleanup: %v\n", err)
			}
		}
	}

	// 1. Create temp user
	tempUser, err := userutil.CreateTempUser()
	if err != nil {
		return err
	}
	cleanups = append(cleanups, tempUser.Cleanup)

	// 2. Grant ACL on CWD
	if err := tempUser.GrantACL(cwd); err != nil {
		cleanup()
		return err
	}

	// 3. Create temp dir for cert bundle (world-readable so the temp user can access it)
	tmpDir, err := os.MkdirTemp("", "boxit-run-")
	if err != nil {
		cleanup()
		return err
	}
	os.Chmod(tmpDir, 0755)
	cleanups = append(cleanups, func() error { return os.RemoveAll(tmpDir) })

	// 4. Start proxy
	p, err := proxy.Start(prof)
	if err != nil {
		cleanup()
		return err
	}
	cleanups = append(cleanups, p.Stop)

	// 5. Install pf rules
	anchor := &netfilter.PFAnchor{Name: tempUser.Username}
	if err := anchor.Install(tempUser.UID, p.Port); err != nil {
		cleanup()
		return err
	}
	cleanups = append(cleanups, anchor.Cleanup)

	// 6. Build cert bundle
	certBundle, err := proxy.BuildCertBundle(p.ConfDir, tmpDir)
	if err != nil {
		cleanup()
		return err
	}

	// 7. Run sandboxed command as temp user
	err = sandbox.RunWithOptions(sandbox.Options{
		CWD:      cwd,
		Args:     args,
		RunAsUID: tempUser.UID,
		ExtraEnv: proxy.CertEnvVars(certBundle),
	})

	cleanup()
	return err
}

// runWithExplicitProxy runs the command in a sandbox with an explicit HTTP proxy.
// This does not require root — it uses http_proxy/https_proxy env vars instead of
// pf-based transparent interception. Tools that ignore proxy env vars will bypass
// the proxy.
func runNetNSChild(_ []string) error {
	return fmt.Errorf("network namespace child is only supported on Linux")
}

func runSandboxChild(_ []string) error {
	return fmt.Errorf("sandbox child is only supported on Linux")
}

func runWithExplicitProxy(cwd string, args []string, prof *profile.Profile) error {
	fmt.Fprintln(os.Stderr, "boxit: running without root — using explicit proxy (http_proxy/https_proxy).")
	fmt.Fprintln(os.Stderr, "boxit: not all tools honor proxy env vars. Run with sudo for full HTTP interception.")

	// Cleanup stack
	var cleanups []func() error
	cleanup := func() {
		slog.Debug("cleanup starting", "count", len(cleanups))
		for i := len(cleanups) - 1; i >= 0; i-- {
			slog.Debug("running cleanup", "index", len(cleanups)-i, "total", len(cleanups))
			if err := cleanups[i](); err != nil {
				fmt.Fprintf(os.Stderr, "boxit: cleanup: %v\n", err)
			}
		}
		slog.Debug("cleanup done")
	}

	// 1. Create temp dir for cert bundle
	slog.Debug("creating temp dir")
	tmpDir, err := os.MkdirTemp("", "boxit-run-")
	if err != nil {
		return err
	}
	cleanups = append(cleanups, func() error { return os.RemoveAll(tmpDir) })

	// 2. Start proxy
	slog.Debug("starting proxy")
	p, err := proxy.Start(prof)
	if err != nil {
		cleanup()
		return err
	}
	slog.Debug("proxy started", "port", p.Port)
	cleanups = append(cleanups, p.Stop)

	// 3. Build cert bundle
	slog.Debug("building cert bundle")
	certBundle, err := proxy.BuildCertBundle(p.ConfDir, tmpDir)
	if err != nil {
		cleanup()
		return err
	}
	slog.Debug("cert bundle ready", "path", certBundle)

	// 4. Run sandboxed command with proxy env vars
	envVars := proxy.CertEnvVars(certBundle)
	envVars = append(envVars, proxy.ProxyEnvVars(p.Port)...)
	slog.Debug("launching sandbox", "args", args, "envCount", len(envVars))

	err = sandbox.RunWithOptions(sandbox.Options{
		CWD:      cwd,
		Args:     args,
		ExtraEnv: envVars,
	})
	slog.Debug("sandbox exited", "err", err)

	cleanup()
	return err
}