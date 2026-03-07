//go:build darwin

package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

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

	// Handle signals for cleanup
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cleanup()
		os.Exit(130)
	}()

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

	// 3. Create temp dir for cert bundle
	tmpDir, err := os.MkdirTemp("", "boxit-run-")
	if err != nil {
		cleanup()
		return err
	}
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