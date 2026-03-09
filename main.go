package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"

	"github.com/masp/boxit/profile"
	"github.com/masp/boxit/sandbox"
	"github.com/masp/boxit/userutil"
)

func main() {
	profileName := flag.String("p", "", "profile name (loads ~/.boxit/<name>.json)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: boxit [-p profile] <command> [args...]\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		flag.Usage()
		os.Exit(1)
	}

	if args[0] == "daemon" {
		if err := userutil.RunDaemon(); err != nil {
			fmt.Fprintf(os.Stderr, "boxit daemon: %v\n", err)
			os.Exit(1)
		}
		return
	}

	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "boxit: failed to get working directory: %v\n", err)
		os.Exit(1)
	}

	// Load profile
	var prof *profile.Profile
	if *profileName != "" {
		prof, err = profile.Load(*profileName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "boxit: %v\n", err)
			os.Exit(1)
		}
	} else {
		prof = profile.Default()
	}

	if prof.NeedsProxy() {
		if os.Geteuid() == 0 {
			// Root: transparent proxy via pf + temp user (catches all HTTP/HTTPS)
			err = runWithProxy(cwd, args, prof)
		} else {
			// Non-root: explicit proxy via env vars (best-effort)
			err = runWithExplicitProxy(cwd, args, prof)
		}
	} else {
		err = sandbox.Run(cwd, args)
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "boxit: %v\n", err)
		os.Exit(1)
	}
}
