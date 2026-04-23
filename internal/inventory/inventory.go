// Copyright 2026 The Surveyor Authors
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/steadytao/surveyor/internal/core"
	"github.com/steadytao/surveyor/internal/debugassert"
	"gopkg.in/yaml.v3"
)

// Document is the canonical imported-inventory representation produced by the
// first structured inventory parser layer.
type Document struct {
	Format     core.InventorySourceFormat
	SourceName string
	Entries    []Entry
}

// Entry records one imported inventory target plus its structured metadata and
// provenance. It remains separate from executable remote scope.
type Entry struct {
	Host            string
	Ports           []int
	Name            string
	Owner           string
	Environment     string
	Tags            []string
	Notes           string
	Provenance      []core.InventoryProvenance
	AdapterWarnings []core.InventoryAdapterWarning
}

// Annotation returns the imported context in the shared core annotation shape.
func (entry Entry) Annotation() *core.InventoryAnnotation {
	return &core.InventoryAnnotation{
		Ports:           append([]int(nil), entry.Ports...),
		Name:            entry.Name,
		Owner:           entry.Owner,
		Environment:     entry.Environment,
		Tags:            append([]string(nil), entry.Tags...),
		Notes:           entry.Notes,
		Provenance:      append([]core.InventoryProvenance(nil), entry.Provenance...),
		AdapterWarnings: cloneAdapterWarnings(entry.AdapterWarnings),
	}
}

func cloneAdapterWarnings(warnings []core.InventoryAdapterWarning) []core.InventoryAdapterWarning {
	if len(warnings) == 0 {
		return nil
	}

	cloned := make([]core.InventoryAdapterWarning, 0, len(warnings))
	for _, warning := range warnings {
		warningClone := warning
		warningClone.Evidence = append([]string(nil), warning.Evidence...)
		cloned = append(cloned, warningClone)
	}

	return cloned
}

type rawManifest struct {
	Version int        `yaml:"version" json:"version"`
	Entries []rawEntry `yaml:"entries" json:"entries"`
}

type rawEntry struct {
	Host        string   `yaml:"host" json:"host"`
	Address     string   `yaml:"address" json:"address"`
	Ports       []int    `yaml:"ports" json:"ports"`
	Name        string   `yaml:"name" json:"name"`
	Owner       string   `yaml:"owner" json:"owner"`
	Environment string   `yaml:"environment" json:"environment"`
	Tags        []string `yaml:"tags" json:"tags"`
	Notes       string   `yaml:"notes" json:"notes"`
}

var supportedCSVHeaders = map[string]struct{}{
	"host":        {},
	"address":     {},
	"ports":       {},
	"name":        {},
	"owner":       {},
	"environment": {},
	"tags":        {},
	"notes":       {},
}

// Load reads an inventory file from disk, infers its format from the file
// extension and returns the canonical imported-inventory model.
func Load(path string) (Document, error) {
	return load(path, "", AdapterOptions{})
}

// LoadWithAdapter reads an inventory file from disk and parses it through one
// registered product-specific adapter.
func LoadWithAdapter(path string, adapterName core.InventoryAdapter, options AdapterOptions) (Document, error) {
	return load(path, normalizeAdapterName(string(adapterName)), options)
}

func load(path string, adapterName core.InventoryAdapter, options AdapterOptions) (Document, error) {
	format, err := detectFormat(path, adapterName)
	if err != nil {
		return Document{}, err
	}

	if adapterName == core.InventoryAdapterCaddy && format == core.InventorySourceFormatCaddyfile {
		return parse(nil, format, path, adapterName, options)
	}

	// #nosec G304 -- inventory paths are explicit operator-provided CLI inputs.
	data, err := os.ReadFile(path)
	if err != nil {
		return Document{}, fmt.Errorf("read inventory file %q: %w", path, err)
	}

	return parse(data, format, path, adapterName, options)
}

// Parse decodes one imported inventory document in the declared format.
func Parse(data []byte, format core.InventorySourceFormat, sourceName string) (Document, error) {
	return parse(data, format, sourceName, "", AdapterOptions{})
}

// ParseWithAdapter decodes one imported inventory document in the declared
// format through one registered product-specific adapter.
func ParseWithAdapter(data []byte, format core.InventorySourceFormat, sourceName string, adapterName core.InventoryAdapter, options AdapterOptions) (Document, error) {
	return parse(data, format, sourceName, normalizeAdapterName(string(adapterName)), options)
}

func parse(data []byte, format core.InventorySourceFormat, sourceName string, adapterName core.InventoryAdapter, options AdapterOptions) (Document, error) {
	if adapterName != "" {
		return parseWithAdapter(data, format, sourceName, adapterName, options)
	}

	switch format {
	case core.InventorySourceFormatYAML:
		return parseYAML(data, sourceName)
	case core.InventorySourceFormatJSON:
		return parseJSON(data, sourceName)
	case core.InventorySourceFormatCSV:
		return parseCSV(data, sourceName)
	default:
		return Document{}, fmt.Errorf("unsupported inventory format %q", format)
	}
}

// DetectAdapter infers one product adapter from an inventory path when the
// file name is unambiguous. It is intentionally conservative.
func DetectAdapter(path string) core.InventoryAdapter {
	if isCaddyfilePath(path) {
		return core.InventoryAdapterCaddy
	}

	return ""
}

func detectFormat(path string, adapterName core.InventoryAdapter) (core.InventorySourceFormat, error) {
	if isCaddyfilePath(path) {
		if adapterName == core.InventoryAdapterCaddy {
			return core.InventorySourceFormatCaddyfile, nil
		}

		return "", fmt.Errorf("unsupported inventory file %q: Caddyfile input requires --adapter caddy", path)
	}

	switch strings.ToLower(filepath.Ext(path)) {
	case ".yaml", ".yml":
		return core.InventorySourceFormatYAML, nil
	case ".json":
		return core.InventorySourceFormatJSON, nil
	case ".csv":
		return core.InventorySourceFormatCSV, nil
	default:
		if adapterName == core.InventoryAdapterCaddy {
			return core.InventorySourceFormatCaddyfile, nil
		}

		return "", fmt.Errorf("unsupported inventory file %q: expected .yaml, .yml, .json or .csv", path)
	}
}

func isCaddyfilePath(path string) bool {
	base := filepath.Base(strings.TrimSpace(path))
	return strings.EqualFold(base, "Caddyfile") || strings.EqualFold(filepath.Ext(base), ".caddyfile")
}

func parseYAML(data []byte, sourceName string) (Document, error) {
	var raw rawManifest
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return Document{}, fmt.Errorf("parse YAML inventory: %w", err)
	}

	return normalizeManifest(raw, core.InventorySourceFormatYAML, sourceName)
}

func parseJSON(data []byte, sourceName string) (Document, error) {
	var raw rawManifest
	if err := json.Unmarshal(data, &raw); err != nil {
		return Document{}, fmt.Errorf("parse JSON inventory: %w", err)
	}

	return normalizeManifest(raw, core.InventorySourceFormatJSON, sourceName)
}

func normalizeManifest(raw rawManifest, format core.InventorySourceFormat, sourceName string) (Document, error) {
	if raw.Version != 1 {
		return Document{}, fmt.Errorf("inventory version must be 1")
	}
	if len(raw.Entries) == 0 {
		return Document{}, fmt.Errorf("inventory must include at least one entry")
	}

	entries := make([]Entry, 0, len(raw.Entries))
	for index, item := range raw.Entries {
		entry, err := normalizeRawEntry(item, fmt.Sprintf("entries[%d]", index), format, sourceName, fmt.Sprintf("entries[%d]", index))
		if err != nil {
			return Document{}, err
		}
		entries = append(entries, entry)
	}

	entries, err := deduplicateEntries(entries)
	if err != nil {
		return Document{}, err
	}

	document := Document{
		Format:     format,
		SourceName: sourceName,
		Entries:    entries,
	}
	assertValidDocument(document)
	return document, nil
}

func parseCSV(data []byte, sourceName string) (Document, error) {
	reader := csv.NewReader(bytes.NewReader(data))
	reader.FieldsPerRecord = -1
	reader.TrimLeadingSpace = true

	records, err := reader.ReadAll()
	if err != nil {
		return Document{}, fmt.Errorf("parse CSV inventory: %w", err)
	}
	if len(records) == 0 {
		return Document{}, fmt.Errorf("inventory CSV must include a header row")
	}

	headerMap, err := normalizeCSVHeader(records[0])
	if err != nil {
		return Document{}, err
	}

	entries := make([]Entry, 0, len(records)-1)
	for rowIndex, record := range records[1:] {
		if rowIsBlank(record) {
			continue
		}

		raw := rawEntry{
			Host:        csvField(record, headerMap, "host"),
			Address:     csvField(record, headerMap, "address"),
			Name:        csvField(record, headerMap, "name"),
			Owner:       csvField(record, headerMap, "owner"),
			Environment: csvField(record, headerMap, "environment"),
			Notes:       csvField(record, headerMap, "notes"),
		}

		ports, err := parseCSVPorts(csvField(record, headerMap, "ports"), rowIndex+2)
		if err != nil {
			return Document{}, err
		}
		raw.Ports = ports
		raw.Tags = parseCSVTags(csvField(record, headerMap, "tags"))

		recordRef := fmt.Sprintf("line %d", rowIndex+2)
		entry, err := normalizeRawEntry(raw, recordRef, core.InventorySourceFormatCSV, sourceName, recordRef)
		if err != nil {
			return Document{}, err
		}
		entries = append(entries, entry)
	}

	if len(entries) == 0 {
		return Document{}, fmt.Errorf("inventory CSV must include at least one entry")
	}

	entries, err = deduplicateEntries(entries)
	if err != nil {
		return Document{}, err
	}

	document := Document{
		Format:     core.InventorySourceFormatCSV,
		SourceName: sourceName,
		Entries:    entries,
	}
	assertValidDocument(document)
	return document, nil
}

func normalizeCSVHeader(header []string) (map[string]int, error) {
	indexes := make(map[string]int, len(header))
	for index, raw := range header {
		name := strings.ToLower(strings.TrimSpace(raw))
		if name == "" {
			return nil, fmt.Errorf("inventory CSV header[%d] must not be empty", index)
		}
		if _, ok := supportedCSVHeaders[name]; !ok {
			return nil, fmt.Errorf("unsupported inventory CSV header %q", raw)
		}
		if _, ok := indexes[name]; ok {
			return nil, fmt.Errorf("duplicate inventory CSV header %q", raw)
		}
		indexes[name] = index
	}

	if _, hasHost := indexes["host"]; !hasHost {
		if _, hasAddress := indexes["address"]; !hasAddress {
			return nil, fmt.Errorf("inventory CSV must include host or address header")
		}
	}

	return indexes, nil
}

func csvField(record []string, indexes map[string]int, name string) string {
	index, ok := indexes[name]
	if !ok || index >= len(record) {
		return ""
	}

	return record[index]
}

func parseCSVPorts(raw string, line int) ([]int, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, nil
	}

	parts := strings.Split(trimmed, ",")
	ports := make([]int, 0, len(parts))
	seen := make(map[int]struct{}, len(parts))
	for index, part := range parts {
		entry := strings.TrimSpace(part)
		if entry == "" {
			return nil, fmt.Errorf("%s.ports[%d] must not be empty", fmt.Sprintf("line %d", line), index)
		}

		port, err := strconv.Atoi(entry)
		if err != nil {
			return nil, fmt.Errorf("%s.ports[%d] must be numeric: %w", fmt.Sprintf("line %d", line), index, err)
		}
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("%s.ports[%d] must be between 1 and 65535", fmt.Sprintf("line %d", line), index)
		}
		if _, ok := seen[port]; ok {
			continue
		}

		seen[port] = struct{}{}
		ports = append(ports, port)
	}

	sort.Ints(ports)
	return ports, nil
}

func parseCSVTags(raw string) []string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil
	}

	return strings.Split(trimmed, ",")
}

func rowIsBlank(record []string) bool {
	for _, field := range record {
		if strings.TrimSpace(field) != "" {
			return false
		}
	}
	return true
}

func normalizeRawEntry(raw rawEntry, pathPrefix string, format core.InventorySourceFormat, sourceName string, sourceRecord string) (Entry, error) {
	host, err := normalizeEntryHost(raw.Host, raw.Address, pathPrefix)
	if err != nil {
		return Entry{}, err
	}

	ports, err := normalizePorts(raw.Ports, pathPrefix)
	if err != nil {
		return Entry{}, err
	}

	entry := Entry{
		Host:        host,
		Ports:       ports,
		Name:        strings.TrimSpace(raw.Name),
		Owner:       strings.TrimSpace(raw.Owner),
		Environment: strings.TrimSpace(raw.Environment),
		Tags:        normalizeTags(raw.Tags),
		Notes:       strings.TrimSpace(raw.Notes),
		Provenance: []core.InventoryProvenance{
			{
				SourceKind:   core.InventorySourceKindInventoryFile,
				SourceFormat: format,
				SourceName:   sourceName,
				SourceRecord: sourceRecord,
			},
		},
	}

	return entry, nil
}

func normalizeEntryHost(host string, address string, pathPrefix string) (string, error) {
	trimmedHost := strings.TrimSpace(host)
	trimmedAddress := strings.TrimSpace(address)

	if trimmedHost == "" && trimmedAddress == "" {
		return "", fmt.Errorf("%s.host or %s.address must not be empty", pathPrefix, pathPrefix)
	}

	hostValue := trimmedHost
	if hostValue == "" {
		hostValue = trimmedAddress
	}

	normalizedHost := normalizeHost(hostValue)
	if trimmedHost != "" && trimmedAddress != "" {
		normalizedAddress := normalizeHost(trimmedAddress)
		if normalizedHost != normalizedAddress {
			return "", fmt.Errorf("%s.host and %s.address must not disagree", pathPrefix, pathPrefix)
		}
	}

	return normalizedHost, nil
}

func normalizeHost(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if len(trimmed) >= 2 && strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
		if address, err := netip.ParseAddr(strings.TrimSpace(trimmed[1 : len(trimmed)-1])); err == nil {
			return address.String()
		}
	}
	if address, err := netip.ParseAddr(trimmed); err == nil {
		return address.String()
	}

	return strings.ToLower(trimmed)
}

func normalizePorts(raw []int, pathPrefix string) ([]int, error) {
	if len(raw) == 0 {
		return nil, nil
	}

	ports := make([]int, 0, len(raw))
	seen := make(map[int]struct{}, len(raw))
	for index, port := range raw {
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("%s.ports[%d] must be between 1 and 65535", pathPrefix, index)
		}
		if _, ok := seen[port]; ok {
			continue
		}

		seen[port] = struct{}{}
		ports = append(ports, port)
	}

	sort.Ints(ports)
	return ports, nil
}

func normalizeTags(raw []string) []string {
	if len(raw) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(raw))
	tags := make([]string, 0, len(raw))
	for _, tag := range raw {
		trimmed := strings.TrimSpace(tag)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}

		seen[trimmed] = struct{}{}
		tags = append(tags, trimmed)
	}

	if len(tags) == 0 {
		return nil
	}

	sort.Strings(tags)
	return tags
}

func deduplicateEntries(entries []Entry) ([]Entry, error) {
	order := make([]string, 0, len(entries))
	byHost := make(map[string]Entry, len(entries))

	for _, entry := range entries {
		existing, ok := byHost[entry.Host]
		if !ok {
			byHost[entry.Host] = entry
			order = append(order, entry.Host)
			continue
		}

		if !sameMetadata(existing, entry) {
			return nil, fmt.Errorf("conflicting inventory metadata for host %q", entry.Host)
		}

		existing.Ports = mergePorts(existing.Ports, entry.Ports)
		existing.Provenance = append(existing.Provenance, entry.Provenance...)
		existing.AdapterWarnings = mergeAdapterWarnings(existing.AdapterWarnings, entry.AdapterWarnings)
		byHost[entry.Host] = existing
	}

	deduplicated := make([]Entry, 0, len(order))
	for _, host := range order {
		deduplicated = append(deduplicated, byHost[host])
	}

	return deduplicated, nil
}

func sameMetadata(left Entry, right Entry) bool {
	return left.Name == right.Name &&
		left.Owner == right.Owner &&
		left.Environment == right.Environment &&
		left.Notes == right.Notes &&
		slicesEqual(left.Tags, right.Tags)
}

func mergePorts(left []int, right []int) []int {
	if len(left) == 0 && len(right) == 0 {
		return nil
	}

	seen := make(map[int]struct{}, len(left)+len(right))
	merged := make([]int, 0, len(left)+len(right))
	for _, port := range left {
		if _, ok := seen[port]; ok {
			continue
		}
		seen[port] = struct{}{}
		merged = append(merged, port)
	}
	for _, port := range right {
		if _, ok := seen[port]; ok {
			continue
		}
		seen[port] = struct{}{}
		merged = append(merged, port)
	}

	sort.Ints(merged)
	return merged
}

func mergeAdapterWarnings(left []core.InventoryAdapterWarning, right []core.InventoryAdapterWarning) []core.InventoryAdapterWarning {
	if len(left) == 0 && len(right) == 0 {
		return nil
	}

	merged := make([]core.InventoryAdapterWarning, 0, len(left)+len(right))
	seen := make(map[string]struct{}, len(left)+len(right))
	appendUnique := func(warnings []core.InventoryAdapterWarning) {
		for _, warning := range warnings {
			key := warning.Code + "\x00" + warning.Summary + "\x00" + strings.Join(warning.Evidence, "\x00")
			if _, ok := seen[key]; ok {
				continue
			}

			seen[key] = struct{}{}
			warningClone := warning
			warningClone.Evidence = append([]string(nil), warning.Evidence...)
			merged = append(merged, warningClone)
		}
	}

	appendUnique(left)
	appendUnique(right)

	return merged
}

func slicesEqual(left []string, right []string) bool {
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

func assertValidDocument(document Document) {
	if !debugassert.Enabled {
		return
	}

	debugassert.That(document.Format != "", "inventory document must have a format")
	debugassert.That(document.SourceName != "", "inventory document must have a source name")
	debugassert.That(len(document.Entries) > 0, "inventory document must contain entries")

	seenHosts := make(map[string]struct{}, len(document.Entries))
	for _, entry := range document.Entries {
		debugassert.That(strings.TrimSpace(entry.Host) != "", "inventory entry host must not be blank")
		debugassert.That(len(entry.Provenance) > 0, "inventory entry %q must retain provenance", entry.Host)
		for index, port := range entry.Ports {
			debugassert.That(port >= 1 && port <= 65535, "inventory entry %q contains invalid port %d", entry.Host, port)
			if index > 0 {
				debugassert.That(entry.Ports[index-1] < port, "inventory entry %q ports must be strictly increasing", entry.Host)
			}
		}
		for index, tag := range entry.Tags {
			debugassert.That(strings.TrimSpace(tag) != "", "inventory entry %q tag %d must not be blank", entry.Host, index)
			if index > 0 {
				debugassert.That(entry.Tags[index-1] < entry.Tags[index], "inventory entry %q tags must be strictly increasing", entry.Host)
			}
		}

		if _, ok := seenHosts[entry.Host]; ok {
			debugassert.That(false, "inventory document contains duplicate host %q after deduplication", entry.Host)
		}
		seenHosts[entry.Host] = struct{}{}
	}
}
