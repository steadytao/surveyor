// Copyright 2026 The Surveyor Authors
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/steadytao/surveyor/internal/core"
)

func TestParseWithCaddyAdapterSimpleConfig(t *testing.T) {
	t.Parallel()

	document, err := ParseWithAdapter([]byte(`{
  "apps": {
    "http": {
      "servers": {
        "myserver": {
          "listen": [":443"],
          "routes": [
            {
              "match": [
                {
                  "host": ["example.com"]
                }
              ],
              "handle": [
                {
                  "handler": "file_server"
                }
              ]
            }
          ]
        }
      }
    }
  }
}`), core.InventorySourceFormatJSON, "caddy.json", core.InventoryAdapterCaddy, AdapterOptions{})
	if err != nil {
		t.Fatalf("ParseWithAdapter() error = %v", err)
	}

	if got, want := len(document.Entries), 1; got != want {
		t.Fatalf("len(document.Entries) = %d, want %d", got, want)
	}

	entry := document.Entries[0]
	if got, want := entry.Host, "example.com"; got != want {
		t.Fatalf("entry.Host = %q, want %q", got, want)
	}
	if got, want := entry.Ports, []int{443}; !intSlicesEqual(got, want) {
		t.Fatalf("entry.Ports = %v, want %v", got, want)
	}
	if got, want := entry.Provenance[0].Adapter, core.InventoryAdapterCaddy; got != want {
		t.Fatalf("entry.Provenance[0].Adapter = %q, want %q", got, want)
	}
	if got, want := entry.Provenance[0].SourceRecord, "apps.http.servers.myserver.routes[0]"; got != want {
		t.Fatalf("entry.Provenance[0].SourceRecord = %q, want %q", got, want)
	}
	if got, want := entry.Provenance[0].SourceObject, "server myserver routes[0]"; got != want {
		t.Fatalf("entry.Provenance[0].SourceObject = %q, want %q", got, want)
	}
}

func TestParseWithCaddyAdapterCaddyfileInput(t *testing.T) {
	useFakeCaddy(t, fakeCaddyAdaptedJSON(), "Caddyfile input is not formatted")

	document, err := ParseWithAdapter([]byte(`
https://api.example.com:8443 {
	respond "ok"
}
`), core.InventorySourceFormatCaddyfile, "Caddyfile", core.InventoryAdapterCaddy, AdapterOptions{})
	if err != nil {
		t.Fatalf("ParseWithAdapter() error = %v", err)
	}

	if got, want := document.Format, core.InventorySourceFormatCaddyfile; got != want {
		t.Fatalf("document.Format = %q, want %q", got, want)
	}
	if got, want := len(document.Entries), 1; got != want {
		t.Fatalf("len(document.Entries) = %d, want %d", got, want)
	}

	entry := document.Entries[0]
	if got, want := entry.Host, "api.example.com"; got != want {
		t.Fatalf("entry.Host = %q, want %q", got, want)
	}
	if got, want := entry.Ports, []int{8443}; !intSlicesEqual(got, want) {
		t.Fatalf("entry.Ports = %v, want %v", got, want)
	}
	if got, want := entry.Provenance[0].SourceFormat, core.InventorySourceFormatCaddyfile; got != want {
		t.Fatalf("entry.Provenance[0].SourceFormat = %q, want %q", got, want)
	}
	if got, want := entry.Provenance[0].Adapter, core.InventoryAdapterCaddy; got != want {
		t.Fatalf("entry.Provenance[0].Adapter = %q, want %q", got, want)
	}
}

func TestParseWithCaddyAdapterEmitsWarningsForIgnoredInputs(t *testing.T) {
	t.Parallel()

	document, err := ParseWithAdapter([]byte(`{
  "apps": {
    "http": {
      "servers": {
        "edge": {
          "listen": ["tcp/:443-444", "udp/:443", "unix//tmp/caddy.sock"],
          "routes": [
            {
              "@id": "site-api",
              "match": [
                {
                  "host": ["api.example.com", "*.example.com", "{http.request.host}"]
                }
              ],
              "handle": [
                {
                  "handler": "reverse_proxy"
                }
              ]
            }
          ]
        }
      }
    }
  }
}`), core.InventorySourceFormatJSON, "caddy.json", core.InventoryAdapterCaddy, AdapterOptions{})
	if err != nil {
		t.Fatalf("ParseWithAdapter() error = %v", err)
	}

	if got, want := len(document.Entries), 1; got != want {
		t.Fatalf("len(document.Entries) = %d, want %d", got, want)
	}

	entry := document.Entries[0]
	if got, want := entry.Host, "api.example.com"; got != want {
		t.Fatalf("entry.Host = %q, want %q", got, want)
	}
	if got, want := entry.Ports, []int{443, 444}; !intSlicesEqual(got, want) {
		t.Fatalf("entry.Ports = %v, want %v", got, want)
	}
	if len(entry.AdapterWarnings) != 4 {
		t.Fatalf("len(entry.AdapterWarnings) = %d, want 4", len(entry.AdapterWarnings))
	}
	if !containsWarningCode(entry.AdapterWarnings, "non-tcp-listener-ignored") {
		t.Fatalf("entry.AdapterWarnings = %#v, want non-tcp-listener-ignored", entry.AdapterWarnings)
	}
	if !containsWarningCode(entry.AdapterWarnings, "non-concrete-host-ignored") {
		t.Fatalf("entry.AdapterWarnings = %#v, want non-concrete-host-ignored", entry.AdapterWarnings)
	}
}

func TestParseWithCaddyAdapterCarriesCaddyfileAdaptationWarnings(t *testing.T) {
	useFakeCaddy(t, fakeCaddyAdaptedJSON(), "Caddyfile input is not formatted")

	document, err := ParseWithAdapter([]byte(`
https://api.example.com:8443 {
respond "ok"
}
`), core.InventorySourceFormatCaddyfile, "Caddyfile", core.InventoryAdapterCaddy, AdapterOptions{})
	if err != nil {
		t.Fatalf("ParseWithAdapter() error = %v", err)
	}

	if got, want := len(document.Entries), 1; got != want {
		t.Fatalf("len(document.Entries) = %d, want %d", got, want)
	}

	entry := document.Entries[0]
	if !containsWarningCode(entry.AdapterWarnings, "caddyfile-adaptation-warning") {
		t.Fatalf("entry.AdapterWarnings = %#v, want caddyfile-adaptation-warning", entry.AdapterWarnings)
	}
}

func TestParseWithCaddyAdapterUsesExplicitBinaryPath(t *testing.T) {
	binaryPath := writeFakeCaddyBinary(t, fakeCaddyAdaptedJSON(), "Caddyfile input is not formatted")

	document, err := ParseWithAdapter([]byte(`
https://api.example.com:8443 {
	respond "ok"
}
`), core.InventorySourceFormatCaddyfile, "Caddyfile", core.InventoryAdapterCaddy, AdapterOptions{
		ExecutablePath: binaryPath,
	})
	if err != nil {
		t.Fatalf("ParseWithAdapter() error = %v", err)
	}

	if got, want := len(document.Entries), 1; got != want {
		t.Fatalf("len(document.Entries) = %d, want %d", got, want)
	}
}

func TestParseWithCaddyAdapterDeduplicatesHostAndMergesWarnings(t *testing.T) {
	t.Parallel()

	document, err := ParseWithAdapter([]byte(`{
  "apps": {
    "http": {
      "servers": {
        "edge": {
          "listen": [":443"],
          "routes": [
            {
              "match": [
                {
                  "host": ["example.com"]
                }
              ],
              "handle": [
                {
                  "handler": "file_server"
                }
              ]
            },
            {
              "@id": "duplicate",
              "match": [
                {
                  "host": ["example.com", "*.example.com"]
                }
              ],
              "handle": [
                {
                  "handler": "reverse_proxy"
                }
              ]
            }
          ]
        }
      }
    }
  }
}`), core.InventorySourceFormatJSON, "caddy.json", core.InventoryAdapterCaddy, AdapterOptions{})
	if err != nil {
		t.Fatalf("ParseWithAdapter() error = %v", err)
	}

	if got, want := len(document.Entries), 1; got != want {
		t.Fatalf("len(document.Entries) = %d, want %d", got, want)
	}

	entry := document.Entries[0]
	if got, want := len(entry.Provenance), 2; got != want {
		t.Fatalf("len(entry.Provenance) = %d, want %d", got, want)
	}
	if !containsWarningCode(entry.AdapterWarnings, "non-concrete-host-ignored") {
		t.Fatalf("entry.AdapterWarnings = %#v, want merged wildcard warning", entry.AdapterWarnings)
	}
}

func TestParseWithCaddyAdapterRejectsNonJSONInput(t *testing.T) {
	t.Parallel()

	_, err := ParseWithAdapter([]byte("version: 1"), core.InventorySourceFormatYAML, "caddy.yaml", core.InventoryAdapterCaddy, AdapterOptions{})
	if err == nil {
		t.Fatal("ParseWithAdapter() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "caddy adapter requires JSON or Caddyfile input") {
		t.Fatalf("ParseWithAdapter() error = %q, want JSON-or-Caddyfile error", err.Error())
	}
}

func intSlicesEqual(left []int, right []int) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func containsWarningCode(warnings []core.InventoryAdapterWarning, want string) bool {
	for _, warning := range warnings {
		if warning.Code == want {
			return true
		}
	}
	return false
}

func TestLoadWithCaddyAdapterUsesJSONExtension(t *testing.T) {
	t.Parallel()

	path := writeFile(t, "caddy.json", `{
  "apps": {
    "http": {
      "servers": {
        "edge": {
          "listen": [":443"],
          "routes": [
            {
              "match": [
                {
                  "host": ["example.com"]
                }
              ]
            }
          ]
        }
      }
    }
  }
}`)

	document, err := LoadWithAdapter(path, core.InventoryAdapterCaddy, AdapterOptions{})
	if err != nil {
		t.Fatalf("LoadWithAdapter() error = %v", err)
	}
	if got, want := len(document.Entries), 1; got != want {
		t.Fatalf("len(document.Entries) = %d, want %d", got, want)
	}
}

func TestLoadWithCaddyAdapterUsesCaddyfilePath(t *testing.T) {
	useFakeCaddy(t, fakeCaddyAdaptedJSON(), "Caddyfile input is not formatted")

	path := writeFile(t, "Caddyfile", `
https://api.example.com:8443 {
	respond "ok"
}
`)

	document, err := LoadWithAdapter(path, core.InventoryAdapterCaddy, AdapterOptions{})
	if err != nil {
		t.Fatalf("LoadWithAdapter() error = %v", err)
	}
	if got, want := document.Format, core.InventorySourceFormatCaddyfile; got != want {
		t.Fatalf("document.Format = %q, want %q", got, want)
	}
	if got, want := len(document.Entries), 1; got != want {
		t.Fatalf("len(document.Entries) = %d, want %d", got, want)
	}
	if got, want := document.Entries[0].Provenance[0].SourceFormat, core.InventorySourceFormatCaddyfile; got != want {
		t.Fatalf("document.Entries[0].Provenance[0].SourceFormat = %q, want %q", got, want)
	}
	if !containsWarningCode(document.Entries[0].AdapterWarnings, "caddyfile-adaptation-warning") {
		t.Fatalf("document.Entries[0].AdapterWarnings = %#v, want caddyfile-adaptation-warning", document.Entries[0].AdapterWarnings)
	}
}

func TestLoadWithCaddyAdapterAcceptsNonStandardCaddyfileName(t *testing.T) {
	useFakeCaddy(t, fakeCaddyAdaptedJSON(), "Caddyfile input is not formatted")

	path := writeFile(t, "site.conf", `
https://api.example.com:8443 {
	respond "ok"
}
`)

	document, err := LoadWithAdapter(path, core.InventoryAdapterCaddy, AdapterOptions{})
	if err != nil {
		t.Fatalf("LoadWithAdapter() error = %v", err)
	}
	if got, want := document.Format, core.InventorySourceFormatCaddyfile; got != want {
		t.Fatalf("document.Format = %q, want %q", got, want)
	}
	if got, want := len(document.Entries), 1; got != want {
		t.Fatalf("len(document.Entries) = %d, want %d", got, want)
	}
}

func TestLoadRejectsCaddyfilePathWithoutAdapter(t *testing.T) {
	t.Parallel()

	path := writeFile(t, "Caddyfile", `
https://api.example.com:8443 {
	respond "ok"
}
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "requires --adapter caddy") {
		t.Fatalf("Load() error = %q, want adapter guidance", err.Error())
	}
}

func fakeCaddyAdaptedJSON() string {
	return `{"apps":{"http":{"servers":{"edge":{"listen":[":8443"],"routes":[{"@id":"site-api","match":[{"host":["api.example.com"]}],"handle":[{"handler":"static_response"}]}]}}}}}`
}

func useFakeCaddy(t *testing.T, jsonOutput string, stderrOutput string) {
	t.Helper()

	t.Setenv("SURVEYOR_CADDY_BIN", writeFakeCaddyBinary(t, jsonOutput, stderrOutput))
}

func writeFakeCaddyBinary(t *testing.T, jsonOutput string, stderrOutput string) string {
	t.Helper()

	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "caddy")
	script := "#!/bin/sh\ncat \"$0.stderr\" 1>&2\ncat \"$0.json\"\n"
	if runtime.GOOS == "windows" {
		binaryPath += ".cmd"
		script = "@echo off\r\ntype \"%~f0.stderr\" 1>&2\r\ntype \"%~f0.json\"\r\n"
	}
	if err := os.WriteFile(binaryPath, []byte(script), 0o755); err != nil {
		t.Fatalf("WriteFile(script) error = %v", err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(binaryPath, 0o755); err != nil {
			t.Fatalf("Chmod(script) error = %v", err)
		}
	}
	if err := os.WriteFile(binaryPath+".json", []byte(jsonOutput), 0o644); err != nil {
		t.Fatalf("WriteFile(script json) error = %v", err)
	}
	if err := os.WriteFile(binaryPath+".stderr", []byte(stderrOutput), 0o644); err != nil {
		t.Fatalf("WriteFile(script stderr) error = %v", err)
	}

	return binaryPath
}
