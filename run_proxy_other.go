//go:build !darwin

package main

import (
	"errors"

	"github.com/masp/boxit/profile"
)

func runWithProxy(cwd string, args []string, prof *profile.Profile) error {
	return errors.New("HTTPS proxy filtering is only supported on macOS")
}