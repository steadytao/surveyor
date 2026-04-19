package config

import (
	"testing"
	"time"
)

func FuzzParseRemoteScopeCIDROnly(f *testing.F) {
	f.Add("10.0.0.0/32", "443", "cautious", 0, 0, 0, int64(0), false)
	f.Add("2001:db8::/128", "443,8443", "balanced", 32, 128, 8, int64(time.Second), true)
	f.Add("bad-cidr", "65536", "invalid", -1, -1, -1, int64(-1), false)

	f.Fuzz(func(t *testing.T, cidr string, ports string, profile string, maxHosts int, maxAttempts int, maxConcurrency int, timeoutNanos int64, dryRun bool) {
		t.Helper()

		timeout := time.Duration(timeoutNanos)
		_, _ = ParseRemoteScope(RemoteScopeInput{
			CIDR:           cidr,
			Ports:          ports,
			Profile:        profile,
			MaxHosts:       maxHosts,
			MaxAttempts:    maxAttempts,
			MaxConcurrency: maxConcurrency,
			Timeout:        timeout,
			DryRun:         dryRun,
		})
	})
}
