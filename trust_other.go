//go:build !darwin && !linux

package main

import "errors"

func runTrust() error {
	return errors.New("boxit trust is only supported on macOS and Linux")
}
