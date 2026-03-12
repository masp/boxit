//go:build !darwin && !linux

package sandbox

import "errors"

var traceEnabled bool

// SetTrace enables sandbox tracing globally (no-op on unsupported platforms).
func SetTrace(enabled bool) {
	traceEnabled = enabled
}

// Options configures the sandbox execution.
type Options struct {
	CWD      string
	Args     []string
	RunAsUID int
	ExtraEnv []string
	Trace    bool
}

// Run is unsupported on non-macOS platforms.
func Run(cwd string, args []string) error {
	return errors.New("boxit: sandboxing is only supported on macOS")
}

// RunWithOptions is unsupported on non-macOS platforms.
func RunWithOptions(opts Options) error {
	return errors.New("boxit: sandboxing is only supported on macOS")
}
