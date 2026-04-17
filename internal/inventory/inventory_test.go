package inventory

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/steadytao/surveyor/internal/core"
)

type stubAdapter struct {
	name  core.InventoryAdapter
	parse func([]byte, core.InventorySourceFormat, string) (Document, error)
}

func (adapter stubAdapter) Name() core.InventoryAdapter {
	return adapter.name
}

func (adapter stubAdapter) Parse(data []byte, format core.InventorySourceFormat, sourceName string) (Document, error) {
	return adapter.parse(data, format, sourceName)
}

func TestParseYAMLInventory(t *testing.T) {
	t.Parallel()

	document, err := Parse([]byte(`
version: 1
entries:
  - host: API.EXAMPLE.COM
    ports: [8443, 443, 443]
    name: Payments API
    owner: payments
    environment: prod
    tags:
      - critical
      - external
    notes: Internet-facing service
`), core.InventorySourceFormatYAML, "inventory.yaml")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if got, want := document.Format, core.InventorySourceFormatYAML; got != want {
		t.Fatalf("document.Format = %q, want %q", got, want)
	}
	if got, want := len(document.Entries), 1; got != want {
		t.Fatalf("len(document.Entries) = %d, want %d", got, want)
	}

	entry := document.Entries[0]
	if got, want := entry.Host, "api.example.com"; got != want {
		t.Fatalf("entry.Host = %q, want %q", got, want)
	}
	if got, want := entry.Ports[0], 443; got != want {
		t.Fatalf("entry.Ports[0] = %d, want %d", got, want)
	}
	if got, want := entry.Ports[1], 8443; got != want {
		t.Fatalf("entry.Ports[1] = %d, want %d", got, want)
	}
	if got, want := entry.Provenance[0].SourceRecord, "entries[0]"; got != want {
		t.Fatalf("entry.Provenance[0].SourceRecord = %q, want %q", got, want)
	}
}

func TestParseJSONInventorySupportsAddressAlias(t *testing.T) {
	t.Parallel()

	document, err := Parse([]byte(`{
  "version": 1,
  "entries": [
    {
      "address": "2001:DB8::1",
      "owner": "network",
      "tags": ["edge"]
    }
  ]
}`), core.InventorySourceFormatJSON, "inventory.json")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	entry := document.Entries[0]
	if got, want := entry.Host, "2001:db8::1"; got != want {
		t.Fatalf("entry.Host = %q, want %q", got, want)
	}
	if got, want := entry.Owner, "network"; got != want {
		t.Fatalf("entry.Owner = %q, want %q", got, want)
	}
}

func TestParseInventoryNormalizesBracketedIPv6(t *testing.T) {
	t.Parallel()

	document, err := Parse([]byte(`
version: 1
entries:
  - host: "[2001:DB8::1]"
    ports: [443]
`), core.InventorySourceFormatYAML, "inventory.yaml")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	entry := document.Entries[0]
	if got, want := entry.Host, "2001:db8::1"; got != want {
		t.Fatalf("entry.Host = %q, want %q", got, want)
	}
}

func TestParseCSVInventory(t *testing.T) {
	t.Parallel()

	document, err := Parse([]byte(`host,ports,name,owner,environment,tags,notes
api.example.com,"443,8443",Payments API,payments,prod,"external,critical",Internet-facing service
`), core.InventorySourceFormatCSV, "cmdb.csv")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	entry := document.Entries[0]
	if got, want := entry.Name, "Payments API"; got != want {
		t.Fatalf("entry.Name = %q, want %q", got, want)
	}
	if got, want := len(entry.Ports), 2; got != want {
		t.Fatalf("len(entry.Ports) = %d, want %d", got, want)
	}
	if got, want := entry.Provenance[0].SourceFormat, core.InventorySourceFormatCSV; got != want {
		t.Fatalf("entry.Provenance[0].SourceFormat = %q, want %q", got, want)
	}
	if got, want := entry.Provenance[0].SourceRecord, "line 2"; got != want {
		t.Fatalf("entry.Provenance[0].SourceRecord = %q, want %q", got, want)
	}
}

func TestParseInventoryRejectsInvalidVersion(t *testing.T) {
	t.Parallel()

	_, err := Parse([]byte(`
version: 2
entries:
  - host: api.example.com
`), core.InventorySourceFormatYAML, "inventory.yaml")
	if err == nil {
		t.Fatal("Parse() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "inventory version must be 1") {
		t.Fatalf("Parse() error = %q, want version error", err.Error())
	}
}

func TestParseInventoryRejectsMissingHostAndAddress(t *testing.T) {
	t.Parallel()

	_, err := Parse([]byte(`
version: 1
entries:
  - owner: payments
`), core.InventorySourceFormatYAML, "inventory.yaml")
	if err == nil {
		t.Fatal("Parse() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "entries[0].host or entries[0].address must not be empty") {
		t.Fatalf("Parse() error = %q, want host/address error", err.Error())
	}
}

func TestParseCSVRejectsInvalidHeader(t *testing.T) {
	t.Parallel()

	_, err := Parse([]byte(`hostname,owner
api.example.com,payments
`), core.InventorySourceFormatCSV, "cmdb.csv")
	if err == nil {
		t.Fatal("Parse() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "unsupported inventory CSV header") && !strings.Contains(err.Error(), "must include host or address header") {
		t.Fatalf("Parse() error = %q, want header error", err.Error())
	}
}

func TestParseInventoryCollapsesExactDuplicates(t *testing.T) {
	t.Parallel()

	document, err := Parse([]byte(`
version: 1
entries:
  - host: api.example.com
    ports: [443]
    owner: payments
  - host: API.EXAMPLE.COM
    ports: [443]
    owner: payments
`), core.InventorySourceFormatYAML, "inventory.yaml")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if got, want := len(document.Entries), 1; got != want {
		t.Fatalf("len(document.Entries) = %d, want %d", got, want)
	}
	if got, want := len(document.Entries[0].Provenance), 2; got != want {
		t.Fatalf("len(document.Entries[0].Provenance) = %d, want %d", got, want)
	}
}

func TestParseInventoryMergesPortsForMatchingMetadata(t *testing.T) {
	t.Parallel()

	document, err := Parse([]byte(`
version: 1
entries:
  - host: api.example.com
    ports: [443]
    owner: payments
  - host: api.example.com
    ports: [8443]
    owner: payments
`), core.InventorySourceFormatYAML, "inventory.yaml")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	entry := document.Entries[0]
	if got, want := len(entry.Ports), 2; got != want {
		t.Fatalf("len(entry.Ports) = %d, want %d", got, want)
	}
	if got, want := entry.Ports[0], 443; got != want {
		t.Fatalf("entry.Ports[0] = %d, want %d", got, want)
	}
	if got, want := entry.Ports[1], 8443; got != want {
		t.Fatalf("entry.Ports[1] = %d, want %d", got, want)
	}
}

func TestParseInventoryRejectsConflictingMetadata(t *testing.T) {
	t.Parallel()

	_, err := Parse([]byte(`
version: 1
entries:
  - host: api.example.com
    owner: payments
  - host: api.example.com
    owner: platform
`), core.InventorySourceFormatYAML, "inventory.yaml")
	if err == nil {
		t.Fatal("Parse() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), `conflicting inventory metadata for host "api.example.com"`) {
		t.Fatalf("Parse() error = %q, want conflict error", err.Error())
	}
}

func TestLoadDetectsFormatFromExtension(t *testing.T) {
	t.Parallel()

	path := writeFile(t, "inventory.yaml", `
version: 1
entries:
  - host: api.example.com
`)

	document, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got, want := document.Format, core.InventorySourceFormatYAML; got != want {
		t.Fatalf("document.Format = %q, want %q", got, want)
	}
}

func TestParseWithAdapterUsesRegisteredAdapter(t *testing.T) {
	t.Parallel()

	adapterName := core.InventoryAdapter("test-adapter")
	if err := RegisterAdapter(stubAdapter{
		name: adapterName,
		parse: func(data []byte, format core.InventorySourceFormat, sourceName string) (Document, error) {
			if got, want := format, core.InventorySourceFormatJSON; got != want {
				return Document{}, fmt.Errorf("format = %q, want %q", got, want)
			}
			if got, want := sourceName, "adapter.json"; got != want {
				return Document{}, fmt.Errorf("sourceName = %q, want %q", got, want)
			}

			return Document{
				Format:     format,
				SourceName: sourceName,
				Entries: []Entry{
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
		UnregisterAdapter(adapterName)
	})

	document, err := ParseWithAdapter([]byte(`{"ignored":true}`), core.InventorySourceFormatJSON, "adapter.json", core.InventoryAdapter("TEST-ADAPTER"))
	if err != nil {
		t.Fatalf("ParseWithAdapter() error = %v", err)
	}

	if got, want := len(document.Entries), 1; got != want {
		t.Fatalf("len(document.Entries) = %d, want %d", got, want)
	}
	if got, want := document.Entries[0].Provenance[0].Adapter, adapterName; got != want {
		t.Fatalf("document.Entries[0].Provenance[0].Adapter = %q, want %q", got, want)
	}
}

func TestParseWithAdapterRejectsUnsupportedAdapter(t *testing.T) {
	t.Parallel()

	_, err := ParseWithAdapter([]byte(`{}`), core.InventorySourceFormatJSON, "adapter.json", core.InventoryAdapter("missing-adapter"))
	if err == nil {
		t.Fatal("ParseWithAdapter() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), `unsupported inventory adapter "missing-adapter"`) {
		t.Fatalf("ParseWithAdapter() error = %q, want unsupported-adapter error", err.Error())
	}
}

func TestRegisterAdapterRejectsDuplicateName(t *testing.T) {
	t.Parallel()

	adapterName := core.InventoryAdapter("duplicate-adapter")
	if err := RegisterAdapter(stubAdapter{
		name: adapterName,
		parse: func(data []byte, format core.InventorySourceFormat, sourceName string) (Document, error) {
			return Document{}, nil
		},
	}); err != nil {
		t.Fatalf("RegisterAdapter() first error = %v", err)
	}
	t.Cleanup(func() {
		UnregisterAdapter(adapterName)
	})

	err := RegisterAdapter(stubAdapter{
		name: adapterName,
		parse: func(data []byte, format core.InventorySourceFormat, sourceName string) (Document, error) {
			return Document{}, nil
		},
	})
	if err == nil {
		t.Fatal("RegisterAdapter() duplicate error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), `inventory adapter "duplicate-adapter" is already registered`) {
		t.Fatalf("RegisterAdapter() duplicate error = %q, want duplicate-name error", err.Error())
	}
}

func TestRegisterAdapterNormalizesName(t *testing.T) {
	t.Parallel()

	adapterName := core.InventoryAdapter("Mixed-Case-Adapter")
	if err := RegisterAdapter(stubAdapter{
		name: adapterName,
		parse: func(data []byte, format core.InventorySourceFormat, sourceName string) (Document, error) {
			return Document{
				Format:     format,
				SourceName: sourceName,
				Entries: []Entry{
					{
						Host: "api.example.com",
					},
				},
			}, nil
		},
	}); err != nil {
		t.Fatalf("RegisterAdapter() error = %v", err)
	}
	t.Cleanup(func() {
		UnregisterAdapter(adapterName)
	})

	if !HasAdapter(core.InventoryAdapter("mixed-case-adapter")) {
		t.Fatal("HasAdapter() = false, want true for normalized name")
	}

	document, err := ParseWithAdapter([]byte(`{}`), core.InventorySourceFormatJSON, "adapter.json", core.InventoryAdapter("mixed-case-adapter"))
	if err != nil {
		t.Fatalf("ParseWithAdapter() error = %v", err)
	}
	if got, want := len(document.Entries), 1; got != want {
		t.Fatalf("len(document.Entries) = %d, want %d", got, want)
	}
}

func TestEntryAnnotationClonesAdapterWarnings(t *testing.T) {
	t.Parallel()

	entry := Entry{
		Host: "api.example.com",
		Provenance: []core.InventoryProvenance{
			{
				SourceKind:   core.InventorySourceKindInventoryFile,
				SourceFormat: core.InventorySourceFormatYAML,
				SourceName:   "ingress.yaml",
				SourceRecord: "documents[0]",
				Adapter:      core.InventoryAdapterKubernetesIngressV1,
				SourceObject: "Ingress/default/payments-api",
			},
		},
		AdapterWarnings: []core.InventoryAdapterWarning{
			{
				Code:     "controller-specific-behaviour",
				Summary:  "The ingress controller may affect effective exposure and TLS handling.",
				Evidence: []string{"adapter=kubernetes-ingress-v1", "source_name=ingress.yaml", "source_object=Ingress/default/payments-api"},
			},
		},
	}

	annotation := entry.Annotation()

	entry.AdapterWarnings[0].Evidence[0] = "mutated"

	if got, want := annotation.AdapterWarnings[0].Evidence[0], "adapter=kubernetes-ingress-v1"; got != want {
		t.Fatalf("annotation.AdapterWarnings[0].Evidence[0] = %q, want %q", got, want)
	}
	if got, want := annotation.Provenance[0].SourceObject, "Ingress/default/payments-api"; got != want {
		t.Fatalf("annotation.Provenance[0].SourceObject = %q, want %q", got, want)
	}
}

func writeFile(t *testing.T, name string, contents string) string {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", path, err)
	}
	return path
}
