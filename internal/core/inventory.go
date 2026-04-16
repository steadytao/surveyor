package core

// InventorySourceKind records the declared class of imported inventory source.
type InventorySourceKind string

const (
	InventorySourceKindInventoryFile InventorySourceKind = "inventory_file"
)

// InventorySourceFormat records the declared file format an imported inventory
// entry came from.
type InventorySourceFormat string

const (
	InventorySourceFormatYAML InventorySourceFormat = "yaml"
	InventorySourceFormatJSON InventorySourceFormat = "json"
	InventorySourceFormatCSV  InventorySourceFormat = "csv"
)

// InventoryProvenance records where one imported inventory entry came from.
type InventoryProvenance struct {
	SourceKind   InventorySourceKind   `json:"source_kind"`
	SourceFormat InventorySourceFormat `json:"source_format,omitempty"`
	SourceName   string                `json:"source_name,omitempty"`
	SourceRecord string                `json:"source_record,omitempty"`
}

// InventoryAnnotation records structured imported-inventory context attached
// to one discovered or audited remote endpoint. It stays separate from the
// executable remote scope contract so imported metadata does not become
// execution identity by accident.
type InventoryAnnotation struct {
	Ports       []int                 `json:"ports,omitempty"`
	Name        string                `json:"name,omitempty"`
	Owner       string                `json:"owner,omitempty"`
	Environment string                `json:"environment,omitempty"`
	Tags        []string              `json:"tags,omitempty"`
	Notes       string                `json:"notes,omitempty"`
	Provenance  []InventoryProvenance `json:"provenance,omitempty"`
}
