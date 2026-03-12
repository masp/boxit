//go:build !darwin && !linux

package main

import (
	"errors"

	"github.com/masp/boxit/profile"
)

func runWithProxy(cwd string, args []string, prof *profile.Profile) error {
	return errors.New("HTTPS proxy filtering is only supported on macOS and Linux")
}

func runWithExplicitProxy(cwd string, args []string, prof *profile.Profile) error {
	return errors.New("HTTPS proxy filtering is only supported on macOS and Linux")
}

func runNetNSChild(args []string) error {
	return errors.New("network namespace child is only supported on Linux")
}

func runSandboxChild(args []string) error {
	return errors.New("sandbox child is only supported on Linux")
}