//go:build debugassert

package debugassert

import "fmt"

// Enabled reports whether debug assertions are active in the current build.
const Enabled = true

// That fails fast when a debug-only invariant does not hold.
func That(condition bool, format string, args ...any) {
	if condition {
		return
	}

	panic(fmt.Sprintf("debug assertion failed: "+format, args...))
}
