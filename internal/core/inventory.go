// Copyright 2026 The Surveyor Authors
// SPDX-License-Identifier: Apache-2.0

package core

// InventorySourceKind records the declared class of imported inventory source.
type InventorySourceKind string

const (
	InventorySourceKindInventoryFile InventorySourceKind = "inventory_file"
)

// InventorySourceFormat records the concrete input form an imported inventory
// entry came from, for example JSON for Caddy JSON or YAML for Kubernetes
// Ingress manifests.
type InventorySourceFormat string

const (
	InventorySourceFormatYAML      InventorySourceFormat = "yaml"
	InventorySourceFormatJSON      InventorySourceFormat = "json"
	InventorySourceFormatCSV       InventorySourceFormat = "csv"
	InventorySourceFormatCaddyfile InventorySourceFormat = "caddyfile"
)

// InventoryAdapter records one explicit product-level adapter family applied to
// imported inventory input. The concrete input form remains in
// InventorySourceFormat.
type InventoryAdapter string

const (
	InventoryAdapterCaddy               InventoryAdapter = "caddy"
	InventoryAdapterKubernetesIngressV1 InventoryAdapter = "kubernetes-ingress-v1"
)

// InventoryAdapterWarning records one non-fatal warning produced while mapping
// platform input into the canonical imported-inventory model.
type InventoryAdapterWarning struct {
	Code     string   `json:"code"`
	Summary  string   `json:"summary"`
	Evidence []string `json:"evidence,omitempty"`
}

// InventoryProvenance records where one imported inventory entry came from.
// SourceObject is product-specific identity such as a Caddy site label or a
// Kubernetes object reference.
type InventoryProvenance struct {
	SourceKind   InventorySourceKind   `json:"source_kind"`
	SourceFormat InventorySourceFormat `json:"source_format,omitempty"`
	SourceName   string                `json:"source_name,omitempty"`
	SourceRecord string                `json:"source_record,omitempty"`
	Adapter      InventoryAdapter      `json:"adapter,omitempty"`
	SourceObject string                `json:"source_object,omitempty"`
}

// InventoryAnnotation records structured imported-inventory context attached
// to one discovered or audited remote endpoint. It stays separate from the
// executable remote scope contract so imported metadata does not become
// execution identity by accident.
type InventoryAnnotation struct {
	Ports           []int                     `json:"ports,omitempty"`
	Name            string                    `json:"name,omitempty"`
	Owner           string                    `json:"owner,omitempty"`
	Environment     string                    `json:"environment,omitempty"`
	Tags            []string                  `json:"tags,omitempty"`
	Notes           string                    `json:"notes,omitempty"`
	Provenance      []InventoryProvenance     `json:"provenance,omitempty"`
	AdapterWarnings []InventoryAdapterWarning `json:"adapter_warnings,omitempty"`
}
