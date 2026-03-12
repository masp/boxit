//go:build !darwin && !linux

package main

import "errors"

func runLearn(cwd string, args []string, saveName string) error {
	return errors.New("boxit learn is only supported on macOS and Linux")
}
