//go:build !darwin

package sandbox

import "errors"

// Options configures the sandbox execution.
type Options struct {
	CWD      string
	Args     []string
	RunAsUID int
	ExtraEnv []string
}

// Run is unsupported on non-macOS platforms.
func Run(cwd string, args []string) error {
	return errors.New("boxit: sandboxing is only supported on macOS")
}

// RunWithOptions is unsupported on non-macOS platforms.
func RunWithOptions(opts Options) error {
	return errors.New("boxit: sandboxing is only supported on macOS")
}
