package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/steadytao/surveyor/internal/core"
	"github.com/steadytao/surveyor/internal/inventory"
)

type stubInventoryAdapter struct {
	name  core.InventoryAdapter
	parse func([]byte, core.InventorySourceFormat, string, inventory.AdapterOptions) (inventory.Document, error)
}

func (adapter stubInventoryAdapter) Name() core.InventoryAdapter {
	return adapter.name
}

func (adapter stubInventoryAdapter) Parse(data []byte, format core.InventorySourceFormat, sourceName string, options inventory.AdapterOptions) (inventory.Document, error) {
	return adapter.parse(data, format, sourceName, options)
}

func TestParseRemoteScopeDefaults(t *testing.T) {
	t.Parallel()

	scope, err := ParseRemoteScope(RemoteScopeInput{
		CIDR:   "10.0.0.23/24",
		Ports:  "8443,443,443",
		DryRun: true,
	})
	if err != nil {
		t.Fatalf("ParseRemoteScope() error = %v", err)
	}

	if got, want := scope.InputKind, RemoteScopeInputKindCIDR; got != want {
		t.Fatalf("scope.InputKind = %q, want %q", got, want)
	}
	if got, want := scope.CIDR.String(), "10.0.0.0/24"; got != want {
		t.Fatalf("scope.CIDR = %q, want %q", got, want)
	}
	if got, want := scope.Profile, RemoteProfileCautious; got != want {
		t.Fatalf("scope.Profile = %q, want %q", got, want)
	}
	if got, want := scope.Ports, []int{443, 8443}; !reflect.DeepEqual(got, want) {
		t.Fatalf("scope.Ports = %v, want %v", got, want)
	}
	if got, want := scope.MaxHosts, defaultRemoteMaxHosts; got != want {
		t.Fatalf("scope.MaxHosts = %d, want %d", got, want)
	}
	if got, want := scope.MaxAttempts, defaultRemoteMaxAttempts; got != want {
		t.Fatalf("scope.MaxAttempts = %d, want %d", got, want)
	}
	if got, want := scope.HostCount, 256; got != want {
		t.Fatalf("scope.HostCount = %d, want %d", got, want)
	}
	if got, want := scope.AttemptCount, 512; got != want {
		t.Fatalf("scope.AttemptCount = %d, want %d", got, want)
	}
	if got, want := scope.MaxConcurrency, 8; got != want {
		t.Fatalf("scope.MaxConcurrency = %d, want %d", got, want)
	}
	if got, want := scope.Timeout, 3*time.Second; got != want {
		t.Fatalf("scope.Timeout = %s, want %s", got, want)
	}
	if !scope.DryRun {
		t.Fatal("scope.DryRun = false, want true")
	}
}

func TestParseRemoteScopeOverrides(t *testing.T) {
	t.Parallel()

	scope, err := ParseRemoteScope(RemoteScopeInput{
		CIDR:           "10.0.0.0/25",
		Ports:          "9443,443",
		Profile:        "balanced",
		MaxHosts:       512,
		MaxAttempts:    1024,
		MaxConcurrency: 12,
		Timeout:        5 * time.Second,
	})
	if err != nil {
		t.Fatalf("ParseRemoteScope() error = %v", err)
	}

	if got, want := scope.Profile, RemoteProfileBalanced; got != want {
		t.Fatalf("scope.Profile = %q, want %q", got, want)
	}
	if got, want := scope.Ports, []int{443, 9443}; !reflect.DeepEqual(got, want) {
		t.Fatalf("scope.Ports = %v, want %v", got, want)
	}
	if got, want := scope.MaxHosts, 512; got != want {
		t.Fatalf("scope.MaxHosts = %d, want %d", got, want)
	}
	if got, want := scope.MaxAttempts, 1024; got != want {
		t.Fatalf("scope.MaxAttempts = %d, want %d", got, want)
	}
	if got, want := scope.HostCount, 128; got != want {
		t.Fatalf("scope.HostCount = %d, want %d", got, want)
	}
	if got, want := scope.AttemptCount, 256; got != want {
		t.Fatalf("scope.AttemptCount = %d, want %d", got, want)
	}
	if got, want := scope.MaxConcurrency, 12; got != want {
		t.Fatalf("scope.MaxConcurrency = %d, want %d", got, want)
	}
	if got, want := scope.Timeout, 5*time.Second; got != want {
		t.Fatalf("scope.Timeout = %s, want %s", got, want)
	}
}

func TestParseRemoteScopeTargetsFile(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	targetsFile := filepath.Join(tempDir, "approved-hosts.txt")
	if err := os.WriteFile(targetsFile, []byte(strings.Join([]string{
		"# approved remote scope",
		"10.0.0.10",
		"",
		"example.com",
		"EXAMPLE.COM",
		"10.0.0.10",
		"2001:db8::10",
	}, "\n")), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	scope, err := ParseRemoteScope(RemoteScopeInput{
		TargetsFile:    targetsFile,
		Ports:          "8443,443",
		Profile:        "balanced",
		MaxHosts:       10,
		MaxConcurrency: 12,
		Timeout:        5 * time.Second,
		DryRun:         true,
	})
	if err != nil {
		t.Fatalf("ParseRemoteScope() error = %v", err)
	}

	if got, want := scope.InputKind, RemoteScopeInputKindTargetsFile; got != want {
		t.Fatalf("scope.InputKind = %q, want %q", got, want)
	}
	if got, want := scope.TargetsFile, targetsFile; got != want {
		t.Fatalf("scope.TargetsFile = %q, want %q", got, want)
	}
	if got, want := scope.Hosts, []string{"10.0.0.10", "example.com", "2001:db8::10"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("scope.Hosts = %v, want %v", got, want)
	}
	if got, want := scope.HostCount, 3; got != want {
		t.Fatalf("scope.HostCount = %d, want %d", got, want)
	}
	if got, want := scope.AttemptCount, 6; got != want {
		t.Fatalf("scope.AttemptCount = %d, want %d", got, want)
	}
	if got, want := scope.Ports, []int{443, 8443}; !reflect.DeepEqual(got, want) {
		t.Fatalf("scope.Ports = %v, want %v", got, want)
	}
	if got, want := scope.Profile, RemoteProfileBalanced; got != want {
		t.Fatalf("scope.Profile = %q, want %q", got, want)
	}
	if got, want := scope.MaxConcurrency, 12; got != want {
		t.Fatalf("scope.MaxConcurrency = %d, want %d", got, want)
	}
	if got, want := scope.Timeout, 5*time.Second; got != want {
		t.Fatalf("scope.Timeout = %s, want %s", got, want)
	}
	if !scope.DryRun {
		t.Fatal("scope.DryRun = false, want true")
	}
}

func TestParseRemoteScopeTargetsFileNormalizesBracketedIPv6(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	targetsFile := filepath.Join(tempDir, "approved-hosts.txt")
	if err := os.WriteFile(targetsFile, []byte(strings.Join([]string{
		"[2001:DB8::10]",
		"2001:db8::10",
	}, "\n")), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	scope, err := ParseRemoteScope(RemoteScopeInput{
		TargetsFile: targetsFile,
		Ports:       "443",
	})
	if err != nil {
		t.Fatalf("ParseRemoteScope() error = %v", err)
	}

	if got, want := scope.Hosts, []string{"2001:db8::10"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("scope.Hosts = %v, want %v", got, want)
	}
}

func TestParseRemoteScopeInventoryFile(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	inventoryFile := filepath.Join(tempDir, "inventory.yaml")
	if err := os.WriteFile(inventoryFile, []byte(strings.Join([]string{
		"version: 1",
		"entries:",
		"  - host: EXAMPLE.COM",
		"    ports: [443, 8443]",
		"    name: External API",
		"    owner: Platform",
		"    environment: prod",
		"    tags: [critical, external]",
		"    notes: imported from cmdb",
		"  - address: 10.0.0.10",
		"    ports: [9443]",
		"    owner: Core",
	}, "\n")), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	scope, err := ParseRemoteScope(RemoteScopeInput{
		InventoryFile:  inventoryFile,
		Ports:          "10443,443",
		Profile:        "balanced",
		MaxHosts:       10,
		MaxConcurrency: 12,
		Timeout:        5 * time.Second,
		DryRun:         true,
	})
	if err != nil {
		t.Fatalf("ParseRemoteScope() error = %v", err)
	}

	if got, want := scope.InputKind, RemoteScopeInputKindInventoryFile; got != want {
		t.Fatalf("scope.InputKind = %q, want %q", got, want)
	}
	if got, want := scope.InventoryFile, inventoryFile; got != want {
		t.Fatalf("scope.InventoryFile = %q, want %q", got, want)
	}
	if got, want := scope.Ports, []int{443, 10443}; !reflect.DeepEqual(got, want) {
		t.Fatalf("scope.Ports = %v, want %v", got, want)
	}
	if got, want := scope.HostCount, 2; got != want {
		t.Fatalf("scope.HostCount = %d, want %d", got, want)
	}
	if got, want := scope.AttemptCount, 4; got != want {
		t.Fatalf("scope.AttemptCount = %d, want %d", got, want)
	}
	if got, want := len(scope.Targets), 2; got != want {
		t.Fatalf("len(scope.Targets) = %d, want %d", got, want)
	}
	if got, want := scope.Targets[0].Host, "example.com"; got != want {
		t.Fatalf("scope.Targets[0].Host = %q, want %q", got, want)
	}
	if got, want := scope.Targets[0].Ports, []int{443, 10443}; !reflect.DeepEqual(got, want) {
		t.Fatalf("scope.Targets[0].Ports = %v, want %v", got, want)
	}
	if scope.Targets[0].Inventory == nil {
		t.Fatal("scope.Targets[0].Inventory = nil, want non-nil")
	}
	if got, want := scope.Targets[0].Inventory.Ports, []int{443, 8443}; !reflect.DeepEqual(got, want) {
		t.Fatalf("scope.Targets[0].Inventory.Ports = %v, want %v", got, want)
	}
	if got, want := scope.Targets[0].Inventory.Owner, "Platform"; got != want {
		t.Fatalf("scope.Targets[0].Inventory.Owner = %q, want %q", got, want)
	}
	if got, want := scope.Targets[1].Host, "10.0.0.10"; got != want {
		t.Fatalf("scope.Targets[1].Host = %q, want %q", got, want)
	}
	if got, want := scope.Targets[1].Ports, []int{443, 10443}; !reflect.DeepEqual(got, want) {
		t.Fatalf("scope.Targets[1].Ports = %v, want %v", got, want)
	}
	if got, want := scope.Profile, RemoteProfileBalanced; got != want {
		t.Fatalf("scope.Profile = %q, want %q", got, want)
	}
	if got, want := scope.MaxConcurrency, 12; got != want {
		t.Fatalf("scope.MaxConcurrency = %d, want %d", got, want)
	}
	if got, want := scope.Timeout, 5*time.Second; got != want {
		t.Fatalf("scope.Timeout = %s, want %s", got, want)
	}
	if !scope.DryRun {
		t.Fatal("scope.DryRun = false, want true")
	}
}

func TestParseRemoteScopeInventoryFileUsesEntryPorts(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	inventoryFile := filepath.Join(tempDir, "inventory.yaml")
	if err := os.WriteFile(inventoryFile, []byte(strings.Join([]string{
		"version: 1",
		"entries:",
		"  - host: Example.com",
		"    ports: [9443, 443, 443]",
	}, "\n")), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	scope, err := ParseRemoteScope(RemoteScopeInput{
		InventoryFile: inventoryFile,
	})
	if err != nil {
		t.Fatalf("ParseRemoteScope() error = %v", err)
	}

	if got := scope.Ports; len(got) != 0 {
		t.Fatalf("scope.Ports = %v, want empty", got)
	}
	if got, want := len(scope.Targets), 1; got != want {
		t.Fatalf("len(scope.Targets) = %d, want %d", got, want)
	}
	if got, want := scope.Targets[0].Host, "example.com"; got != want {
		t.Fatalf("scope.Targets[0].Host = %q, want %q", got, want)
	}
	if got, want := scope.Targets[0].Ports, []int{443, 9443}; !reflect.DeepEqual(got, want) {
		t.Fatalf("scope.Targets[0].Ports = %v, want %v", got, want)
	}
	if got, want := scope.AttemptCount, 2; got != want {
		t.Fatalf("scope.AttemptCount = %d, want %d", got, want)
	}
}

func TestParseRemoteScopeRejectsExpandedAttemptCountBeyondLimit(t *testing.T) {
	t.Parallel()

	_, err := ParseRemoteScope(RemoteScopeInput{
		CIDR:        "10.0.0.0/30",
		Ports:       "443,8443",
		MaxAttempts: 4,
	})
	if err == nil {
		t.Fatal("ParseRemoteScope() error = nil, want max-attempts rejection")
	}
	if !strings.Contains(err.Error(), "--cidr expands to 8 host:port attempts") {
		t.Fatalf("ParseRemoteScope() error = %v, want expanded attempt-count rejection", err)
	}
}

func TestParseRemoteScopeInventoryFileUsesRegisteredAdapter(t *testing.T) {
	t.Parallel()

	adapterName := core.InventoryAdapter("test-adapter")
	if err := inventory.RegisterAdapter(stubInventoryAdapter{
		name: adapterName,
		parse: func(data []byte, format core.InventorySourceFormat, sourceName string, _ inventory.AdapterOptions) (inventory.Document, error) {
			if got, want := format, core.InventorySourceFormatJSON; got != want {
				return inventory.Document{}, fmt.Errorf("format = %q, want %q", got, want)
			}
			if got, want := filepath.Base(sourceName), "adapter.json"; got != want {
				return inventory.Document{}, fmt.Errorf("sourceName = %q, want %q", got, want)
			}

			return inventory.Document{
				Format:     format,
				SourceName: sourceName,
				Entries: []inventory.Entry{
					{
						Host:  "api.example.com",
						Ports: []int{443},
						Provenance: []core.InventoryProvenance{
							{
								SourceKind:   core.InventorySourceKindInventoryFile,
								SourceFormat: core.InventorySourceFormatJSON,
								SourceName:   sourceName,
								SourceRecord: "records[0]",
								Adapter:      adapterName,
								SourceObject: "object-0",
							},
						},
					},
				},
			}, nil
		},
	}); err != nil {
		t.Fatalf("RegisterAdapter() error = %v", err)
	}
	t.Cleanup(func() {
		inventory.UnregisterAdapter(adapterName)
	})

	tempDir := t.TempDir()
	inventoryFile := filepath.Join(tempDir, "adapter.json")
	if err := os.WriteFile(inventoryFile, []byte(`{"ignored":true}`), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	scope, err := ParseRemoteScope(RemoteScopeInput{
		InventoryFile: inventoryFile,
		Adapter:       string(adapterName),
	})
	if err != nil {
		t.Fatalf("ParseRemoteScope() error = %v", err)
	}

	if got, want := scope.Adapter, adapterName; got != want {
		t.Fatalf("scope.Adapter = %q, want %q", got, want)
	}
	if got, want := len(scope.Targets), 1; got != want {
		t.Fatalf("len(scope.Targets) = %d, want %d", got, want)
	}
	if scope.Targets[0].Inventory == nil {
		t.Fatal("scope.Targets[0].Inventory = nil, want non-nil")
	}
	if got, want := scope.Targets[0].Inventory.Provenance[0].Adapter, adapterName; got != want {
		t.Fatalf("scope.Targets[0].Inventory.Provenance[0].Adapter = %q, want %q", got, want)
	}
}

func TestParseRemoteScopeInventoryFileUsesCaddyAdapter(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	inventoryFile := filepath.Join(tempDir, "caddy.json")
	if err := os.WriteFile(inventoryFile, []byte(`{
  "apps": {
    "http": {
      "servers": {
        "edge": {
          "listen": [":443", ":80"],
          "routes": [
            {
              "@id": "site-api",
              "match": [
                {
                  "host": ["api.example.com"]
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
}`), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	scope, err := ParseRemoteScope(RemoteScopeInput{
		InventoryFile: inventoryFile,
		Adapter:       string(core.InventoryAdapterCaddy),
	})
	if err != nil {
		t.Fatalf("ParseRemoteScope() error = %v", err)
	}

	if got, want := scope.Adapter, core.InventoryAdapterCaddy; got != want {
		t.Fatalf("scope.Adapter = %q, want %q", got, want)
	}
	if got, want := len(scope.Targets), 1; got != want {
		t.Fatalf("len(scope.Targets) = %d, want %d", got, want)
	}
	if got, want := scope.Targets[0].Host, "api.example.com"; got != want {
		t.Fatalf("scope.Targets[0].Host = %q, want %q", got, want)
	}
	if got, want := scope.Targets[0].Ports, []int{80, 443}; !reflect.DeepEqual(got, want) {
		t.Fatalf("scope.Targets[0].Ports = %v, want %v", got, want)
	}
	if scope.Targets[0].Inventory == nil {
		t.Fatal("scope.Targets[0].Inventory = nil, want non-nil")
	}
	if got, want := scope.Targets[0].Inventory.Provenance[0].SourceObject, "server edge @id site-api"; got != want {
		t.Fatalf("scope.Targets[0].Inventory.Provenance[0].SourceObject = %q, want %q", got, want)
	}
}

func TestParseRemoteScopeInventoryFileAutoDetectsCaddyAdapterFromCaddyfile(t *testing.T) {
	useFakeCaddy(t, fakeCaddyAdaptedJSON(), "Caddyfile input is not formatted")

	tempDir := t.TempDir()
	inventoryFile := filepath.Join(tempDir, "Caddyfile")
	if err := os.WriteFile(inventoryFile, []byte(`
https://api.example.com:8443 {
	respond "ok"
}
`), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	scope, err := ParseRemoteScope(RemoteScopeInput{
		InventoryFile: inventoryFile,
	})
	if err != nil {
		t.Fatalf("ParseRemoteScope() error = %v", err)
	}

	if got, want := scope.Adapter, core.InventoryAdapterCaddy; got != want {
		t.Fatalf("scope.Adapter = %q, want %q", got, want)
	}
	if got, want := len(scope.Targets), 1; got != want {
		t.Fatalf("len(scope.Targets) = %d, want %d", got, want)
	}
	if got, want := scope.Targets[0].Host, "api.example.com"; got != want {
		t.Fatalf("scope.Targets[0].Host = %q, want %q", got, want)
	}
	if got, want := scope.Targets[0].Ports, []int{8443}; !reflect.DeepEqual(got, want) {
		t.Fatalf("scope.Targets[0].Ports = %v, want %v", got, want)
	}
	if scope.Targets[0].Inventory == nil {
		t.Fatal("scope.Targets[0].Inventory = nil, want non-nil")
	}
	if got, want := scope.Targets[0].Inventory.Provenance[0].SourceFormat, core.InventorySourceFormatCaddyfile; got != want {
		t.Fatalf("scope.Targets[0].Inventory.Provenance[0].SourceFormat = %q, want %q", got, want)
	}
	if got, want := scope.Targets[0].Inventory.Provenance[0].Adapter, core.InventoryAdapterCaddy; got != want {
		t.Fatalf("scope.Targets[0].Inventory.Provenance[0].Adapter = %q, want %q", got, want)
	}
}

func TestParseRemoteScopeInventoryFileUsesAdapterBinaryOverride(t *testing.T) {
	binaryPath := writeFakeCaddyBinary(t, fakeCaddyAdaptedJSON(), "Caddyfile input is not formatted")

	tempDir := t.TempDir()
	inventoryFile := filepath.Join(tempDir, "Caddyfile")
	if err := os.WriteFile(inventoryFile, []byte(`
https://api.example.com:8443 {
	respond "ok"
}
`), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	scope, err := ParseRemoteScope(RemoteScopeInput{
		InventoryFile: inventoryFile,
		AdapterBinary: binaryPath,
	})
	if err != nil {
		t.Fatalf("ParseRemoteScope() error = %v", err)
	}

	if got, want := scope.Adapter, core.InventoryAdapterCaddy; got != want {
		t.Fatalf("scope.Adapter = %q, want %q", got, want)
	}
	if got, want := len(scope.Targets), 1; got != want {
		t.Fatalf("len(scope.Targets) = %d, want %d", got, want)
	}
}

func TestParseRemoteScopeInventoryFileUsesExplicitCaddyAdapterWithNonStandardFileName(t *testing.T) {
	useFakeCaddy(t, fakeCaddyAdaptedJSON(), "Caddyfile input is not formatted")

	tempDir := t.TempDir()
	inventoryFile := filepath.Join(tempDir, "site.conf")
	if err := os.WriteFile(inventoryFile, []byte(`
https://api.example.com:8443 {
	respond "ok"
}
`), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	scope, err := ParseRemoteScope(RemoteScopeInput{
		InventoryFile: inventoryFile,
		Adapter:       string(core.InventoryAdapterCaddy),
	})
	if err != nil {
		t.Fatalf("ParseRemoteScope() error = %v", err)
	}

	if got, want := scope.Adapter, core.InventoryAdapterCaddy; got != want {
		t.Fatalf("scope.Adapter = %q, want %q", got, want)
	}
	if got, want := len(scope.Targets), 1; got != want {
		t.Fatalf("len(scope.Targets) = %d, want %d", got, want)
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

func TestParseRemoteScopeInventoryFileUsesKubernetesIngressAdapter(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	inventoryFile := filepath.Join(tempDir, "ingress.yaml")
	if err := os.WriteFile(inventoryFile, []byte(`
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: payments-api
  namespace: payments
spec:
  ingressClassName: nginx
  tls:
    - hosts:
        - api.example.com
      secretName: payments-api-tls
  rules:
    - host: api.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: payments-api
                port:
                  number: 80
`), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	scope, err := ParseRemoteScope(RemoteScopeInput{
		InventoryFile: inventoryFile,
		Adapter:       string(core.InventoryAdapterKubernetesIngressV1),
	})
	if err != nil {
		t.Fatalf("ParseRemoteScope() error = %v", err)
	}

	if got, want := scope.Adapter, core.InventoryAdapterKubernetesIngressV1; got != want {
		t.Fatalf("scope.Adapter = %q, want %q", got, want)
	}
	if got, want := len(scope.Targets), 1; got != want {
		t.Fatalf("len(scope.Targets) = %d, want %d", got, want)
	}
	if got, want := scope.Targets[0].Host, "api.example.com"; got != want {
		t.Fatalf("scope.Targets[0].Host = %q, want %q", got, want)
	}
	if got, want := scope.Targets[0].Ports, []int{80, 443}; !reflect.DeepEqual(got, want) {
		t.Fatalf("scope.Targets[0].Ports = %v, want %v", got, want)
	}
	if scope.Targets[0].Inventory == nil {
		t.Fatal("scope.Targets[0].Inventory = nil, want non-nil")
	}
	if got, want := scope.Targets[0].Inventory.Provenance[0].SourceObject, "Ingress/payments/payments-api"; got != want {
		t.Fatalf("scope.Targets[0].Inventory.Provenance[0].SourceObject = %q, want %q", got, want)
	}
}

func TestParseRemoteScopeProfileDefaults(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name               string
		profile            string
		wantProfile        RemoteProfile
		wantMaxConcurrency int
		wantTimeout        time.Duration
	}{
		{
			name:               "cautious",
			profile:            "cautious",
			wantProfile:        RemoteProfileCautious,
			wantMaxConcurrency: 8,
			wantTimeout:        3 * time.Second,
		},
		{
			name:               "balanced",
			profile:            "balanced",
			wantProfile:        RemoteProfileBalanced,
			wantMaxConcurrency: 24,
			wantTimeout:        2 * time.Second,
		},
		{
			name:               "aggressive",
			profile:            "aggressive",
			wantProfile:        RemoteProfileAggressive,
			wantMaxConcurrency: 64,
			wantTimeout:        1 * time.Second,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			scope, err := ParseRemoteScope(RemoteScopeInput{
				CIDR:    "10.0.0.0/24",
				Ports:   "443",
				Profile: testCase.profile,
			})
			if err != nil {
				t.Fatalf("ParseRemoteScope() error = %v", err)
			}

			if got, want := scope.Profile, testCase.wantProfile; got != want {
				t.Fatalf("scope.Profile = %q, want %q", got, want)
			}
			if got, want := scope.MaxConcurrency, testCase.wantMaxConcurrency; got != want {
				t.Fatalf("scope.MaxConcurrency = %d, want %d", got, want)
			}
			if got, want := scope.Timeout, testCase.wantTimeout; got != want {
				t.Fatalf("scope.Timeout = %s, want %s", got, want)
			}
		})
	}
}

func TestParseRemoteScopeInvalidInput(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		input       RemoteScopeInput
		wantErrText string
	}{
		{
			name: "missing scope",
			input: RemoteScopeInput{
				Ports: "443",
			},
			wantErrText: "one of --cidr, --targets-file or --inventory-file is required",
		},
		{
			name: "conflicting scope inputs",
			input: RemoteScopeInput{
				CIDR:        "10.0.0.0/24",
				TargetsFile: "approved-hosts.txt",
				Ports:       "443",
			},
			wantErrText: "use exactly one of --cidr, --targets-file or --inventory-file",
		},
		{
			name: "adapter without inventory file",
			input: RemoteScopeInput{
				CIDR:    "10.0.0.0/24",
				Ports:   "443",
				Adapter: "caddy",
			},
			wantErrText: "--adapter requires --inventory-file",
		},
		{
			name: "adapter binary without inventory file",
			input: RemoteScopeInput{
				CIDR:          "10.0.0.0/24",
				Ports:         "443",
				AdapterBinary: "caddy",
			},
			wantErrText: "--adapter-bin requires --inventory-file",
		},
		{
			name: "invalid cidr",
			input: RemoteScopeInput{
				CIDR:  "10.0.0.0/99",
				Ports: "443",
			},
			wantErrText: "invalid --cidr",
		},
		{
			name: "missing targets file",
			input: RemoteScopeInput{
				TargetsFile: "missing-targets.txt",
				Ports:       "443",
			},
			wantErrText: "read --targets-file",
		},
		{
			name: "missing ports",
			input: RemoteScopeInput{
				CIDR: "10.0.0.0/24",
			},
			wantErrText: "--ports is required",
		},
		{
			name: "blank port entry",
			input: RemoteScopeInput{
				CIDR:  "10.0.0.0/24",
				Ports: "443, ,8443",
			},
			wantErrText: "--ports[1] must not be empty",
		},
		{
			name: "non numeric port",
			input: RemoteScopeInput{
				CIDR:  "10.0.0.0/24",
				Ports: "443,https",
			},
			wantErrText: "--ports[1] must be numeric",
		},
		{
			name: "port out of range",
			input: RemoteScopeInput{
				CIDR:  "10.0.0.0/24",
				Ports: "70000",
			},
			wantErrText: "--ports[0] must be between 1 and 65535",
		},
		{
			name: "invalid profile",
			input: RemoteScopeInput{
				CIDR:    "10.0.0.0/24",
				Ports:   "443",
				Profile: "reckless",
			},
			wantErrText: "invalid --profile",
		},
		{
			name: "negative max hosts",
			input: RemoteScopeInput{
				CIDR:     "10.0.0.0/24",
				Ports:    "443",
				MaxHosts: -1,
			},
			wantErrText: "--max-hosts must not be negative",
		},
		{
			name: "negative max concurrency",
			input: RemoteScopeInput{
				CIDR:           "10.0.0.0/24",
				Ports:          "443",
				MaxConcurrency: -1,
			},
			wantErrText: "--max-concurrency must not be negative",
		},
		{
			name: "negative timeout",
			input: RemoteScopeInput{
				CIDR:    "10.0.0.0/24",
				Ports:   "443",
				Timeout: -1 * time.Second,
			},
			wantErrText: "--timeout must not be negative",
		},
		{
			name: "scope exceeds max hosts",
			input: RemoteScopeInput{
				CIDR:     "10.0.0.0/24",
				Ports:    "443",
				MaxHosts: 64,
			},
			wantErrText: "exceeds --max-hosts=64",
		},
		{
			name: "host count too large",
			input: RemoteScopeInput{
				CIDR:  "2001:db8::/64",
				Ports: "443",
			},
			wantErrText: "host count is too large to support",
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			_, err := ParseRemoteScope(testCase.input)
			if err == nil {
				t.Fatal("ParseRemoteScope() error = nil, want non-nil")
			}

			if !strings.Contains(err.Error(), testCase.wantErrText) {
				t.Fatalf("ParseRemoteScope() error = %q, want substring %q", err.Error(), testCase.wantErrText)
			}
		})
	}
}

func TestParseRemoteScopeTargetsFileInvalidInput(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()

	testCases := []struct {
		name        string
		fileContent string
		maxHosts    int
		wantErrText string
	}{
		{
			name:        "empty after comments",
			fileContent: "# nothing here\n\n   \n# still nothing\n",
			wantErrText: "does not contain any hosts",
		},
		{
			name:        "exceeds host cap",
			fileContent: "10.0.0.10\n10.0.0.11\n10.0.0.12\n",
			maxHosts:    2,
			wantErrText: "exceeds --max-hosts=2",
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			targetsFile := filepath.Join(tempDir, testCase.name+".txt")
			if err := os.WriteFile(targetsFile, []byte(testCase.fileContent), 0o644); err != nil {
				t.Fatalf("WriteFile() error = %v", err)
			}

			_, err := ParseRemoteScope(RemoteScopeInput{
				TargetsFile: targetsFile,
				Ports:       "443",
				MaxHosts:    testCase.maxHosts,
			})
			if err == nil {
				t.Fatal("ParseRemoteScope() error = nil, want non-nil")
			}

			if !strings.Contains(err.Error(), testCase.wantErrText) {
				t.Fatalf("ParseRemoteScope() error = %q, want substring %q", err.Error(), testCase.wantErrText)
			}
		})
	}
}

func TestParseRemoteScopeInventoryFileInvalidInput(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()

	t.Run("missing file", func(t *testing.T) {
		t.Parallel()

		_, err := ParseRemoteScope(RemoteScopeInput{
			InventoryFile: filepath.Join(tempDir, "missing.yaml"),
		})
		if err == nil {
			t.Fatal("ParseRemoteScope() error = nil, want non-nil")
		}
		if !strings.Contains(err.Error(), "load --inventory-file") {
			t.Fatalf("ParseRemoteScope() error = %q, want inventory load error", err.Error())
		}
	})

	t.Run("exceeds host cap", func(t *testing.T) {
		t.Parallel()

		inventoryFile := filepath.Join(tempDir, "exceeds.yaml")
		if err := os.WriteFile(inventoryFile, []byte(strings.Join([]string{
			"version: 1",
			"entries:",
			"  - host: one.example",
			"    ports: [443]",
			"  - host: two.example",
			"    ports: [443]",
			"  - host: three.example",
			"    ports: [443]",
		}, "\n")), 0o644); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}

		_, err := ParseRemoteScope(RemoteScopeInput{
			InventoryFile: inventoryFile,
			MaxHosts:      2,
		})
		if err == nil {
			t.Fatal("ParseRemoteScope() error = nil, want non-nil")
		}
		if !strings.Contains(err.Error(), "exceeds --max-hosts=2") {
			t.Fatalf("ParseRemoteScope() error = %q, want host-cap error", err.Error())
		}
	})

	t.Run("missing entry ports without override", func(t *testing.T) {
		t.Parallel()

		inventoryFile := filepath.Join(tempDir, "missing-ports.yaml")
		if err := os.WriteFile(inventoryFile, []byte(strings.Join([]string{
			"version: 1",
			"entries:",
			"  - host: example.com",
		}, "\n")), 0o644); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}

		_, err := ParseRemoteScope(RemoteScopeInput{
			InventoryFile: inventoryFile,
		})
		if err == nil {
			t.Fatal("ParseRemoteScope() error = nil, want non-nil")
		}
		if !strings.Contains(err.Error(), "does not declare any ports and --ports was not provided") {
			t.Fatalf("ParseRemoteScope() error = %q, want missing-port error", err.Error())
		}
	})

	t.Run("unsupported adapter", func(t *testing.T) {
		t.Parallel()

		inventoryFile := filepath.Join(tempDir, "adapter.json")
		if err := os.WriteFile(inventoryFile, []byte(`{"ignored":true}`), 0o644); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}

		_, err := ParseRemoteScope(RemoteScopeInput{
			InventoryFile: inventoryFile,
			Adapter:       "missing-adapter",
		})
		if err == nil {
			t.Fatal("ParseRemoteScope() error = nil, want non-nil")
		}
		if !strings.Contains(err.Error(), `unsupported --adapter "missing-adapter"`) {
			t.Fatalf("ParseRemoteScope() error = %q, want unsupported-adapter error", err.Error())
		}
	})
}
