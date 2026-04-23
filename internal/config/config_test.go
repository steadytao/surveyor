// Copyright 2026 The Surveyor Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

func TestParseValidConfig(t *testing.T) {
	t.Parallel()

	cfg, err := Parse([]byte(`
targets:
  - name: primary-site
    host: example.com
    port: 443
    tags:
      - external
      - prod
  - host: api.example.com
    port: 8443
    tags:
      - api
      - "  "
`))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if len(cfg.Targets) != 2 {
		t.Fatalf("len(cfg.Targets) = %d, want 2", len(cfg.Targets))
	}

	first := cfg.Targets[0]
	if first.Name != "primary-site" {
		t.Fatalf("first.Name = %q, want %q", first.Name, "primary-site")
	}
	if first.Host != "example.com" {
		t.Fatalf("first.Host = %q, want %q", first.Host, "example.com")
	}
	if first.Port != 443 {
		t.Fatalf("first.Port = %d, want 443", first.Port)
	}
	if got, want := len(first.Tags), 2; got != want {
		t.Fatalf("len(first.Tags) = %d, want %d", got, want)
	}

	second := cfg.Targets[1]
	if second.Name != "" {
		t.Fatalf("second.Name = %q, want empty", second.Name)
	}
	if got, want := len(second.Tags), 1; got != want {
		t.Fatalf("len(second.Tags) = %d, want %d", got, want)
	}
	if second.Tags[0] != "api" {
		t.Fatalf("second.Tags[0] = %q, want %q", second.Tags[0], "api")
	}
}

func TestParseValidConfigNormalizesBracketedIPv6Host(t *testing.T) {
	t.Parallel()

	cfg, err := Parse([]byte(`
targets:
  - host: "[2001:db8::1]"
    port: 443
`))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if got, want := cfg.Targets[0].Host, "2001:db8::1"; got != want {
		t.Fatalf("cfg.Targets[0].Host = %q, want %q", got, want)
	}
}

func TestParseInvalidConfig(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		input       string
		wantErrText string
	}{
		{
			name: "missing targets",
			input: `
name: surveyor
`,
			wantErrText: "config must include at least one target",
		},
		{
			name: "empty host",
			input: `
targets:
  - host: "   "
    port: 443
`,
			wantErrText: "targets[0].host must not be empty",
		},
		{
			name: "missing host",
			input: `
targets:
  - port: 443
`,
			wantErrText: "targets[0].host must not be empty",
		},
		{
			name: "zero port",
			input: `
targets:
  - host: example.com
    port: 0
`,
			wantErrText: "targets[0].port must be between 1 and 65535",
		},
		{
			name: "port too large",
			input: `
targets:
  - host: example.com
    port: 65536
`,
			wantErrText: "targets[0].port must be between 1 and 65535",
		},
		{
			name: "blank name",
			input: `
targets:
  - name: "   "
    host: example.com
    port: 443
`,
			wantErrText: "targets[0].name must not be blank",
		},
		{
			name: "invalid yaml",
			input: `
targets:
  - host: example.com
    port: [443
`,
			wantErrText: "parse YAML config",
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			_, err := Parse([]byte(testCase.input))
			if err == nil {
				t.Fatal("Parse() error = nil, want non-nil")
			}

			if !strings.Contains(err.Error(), testCase.wantErrText) {
				t.Fatalf("Parse() error = %q, want substring %q", err.Error(), testCase.wantErrText)
			}
		})
	}
}
