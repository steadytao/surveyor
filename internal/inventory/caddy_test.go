package inventory

import (
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
}`), core.InventorySourceFormatJSON, "caddy.json", core.InventoryAdapterCaddy)
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
}`), core.InventorySourceFormatJSON, "caddy.json", core.InventoryAdapterCaddy)
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
}`), core.InventorySourceFormatJSON, "caddy.json", core.InventoryAdapterCaddy)
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

	_, err := ParseWithAdapter([]byte("version: 1"), core.InventorySourceFormatYAML, "caddy.yaml", core.InventoryAdapterCaddy)
	if err == nil {
		t.Fatal("ParseWithAdapter() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "caddy adapter requires JSON input") {
		t.Fatalf("ParseWithAdapter() error = %q, want JSON-only error", err.Error())
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

	document, err := LoadWithAdapter(path, core.InventoryAdapterCaddy)
	if err != nil {
		t.Fatalf("LoadWithAdapter() error = %v", err)
	}
	if got, want := len(document.Entries), 1; got != want {
		t.Fatalf("len(document.Entries) = %d, want %d", got, want)
	}
}
