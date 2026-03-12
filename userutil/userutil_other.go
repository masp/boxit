//go:build !darwin

package userutil

import "errors"

// RunDaemon is not supported on non-macOS platforms.
// The daemon is only needed for macOS temp user management.
func RunDaemon() error {
	return errors.New("boxit daemon is only supported on macOS")
}
