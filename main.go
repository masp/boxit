package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"

	"github.com/masp/boxit/profile"
	"github.com/masp/boxit/sandbox"
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

	// Use proxy mode when:
	// - A profile is explicitly specified (-p flag), OR
	// - Running as root (allows sudo ./boxit to use default profile filtering)
	// The built-in transparent proxy handles HTTPS filtering.
	useProxy := prof.NeedsProxy() && (*profileName != "" || os.Geteuid() == 0)

	if useProxy {
		err = runWithProxy(cwd, args, prof)
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
