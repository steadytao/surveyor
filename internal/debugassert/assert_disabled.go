//go:build !debugassert

package debugassert

// Enabled reports whether debug assertions are active in the current build.
const Enabled = false

// That is a no-op outside debug assertion builds.
func That(_ bool, _ string, _ ...any) {}
