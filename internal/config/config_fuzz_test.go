package config

import "testing"

func FuzzParseConfig(f *testing.F) {
	f.Add([]byte("targets:\n  - host: example.com\n    port: 443\n"))
	f.Add([]byte("targets:\n  - host: 127.0.0.1\n    port: 8443\n    tags: [internal]\n"))
	f.Add([]byte("{}"))

	f.Fuzz(func(t *testing.T, data []byte) {
		t.Helper()
		_, _ = Parse(data)
	})
}
