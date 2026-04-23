// Copyright 2026 The Surveyor Authors
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"fmt"
	"strings"
	"sync"

	"github.com/steadytao/surveyor/internal/core"
)

// Adapter parses one product-specific source and maps it into the canonical
// imported-inventory model.
type Adapter interface {
	Name() core.InventoryAdapter
	Parse(data []byte, format core.InventorySourceFormat, sourceName string, options AdapterOptions) (Document, error)
}

// AdapterOptions carries adapter-specific execution inputs that are not part
// of the canonical imported-inventory model, such as helper executable paths.
type AdapterOptions struct {
	ExecutablePath string
}

var (
	adapterRegistryMu sync.RWMutex
	adapterRegistry   = map[core.InventoryAdapter]Adapter{}
)

// RegisterAdapter adds one product-specific adapter to the inventory registry.
func RegisterAdapter(adapter Adapter) error {
	if adapter == nil {
		return fmt.Errorf("inventory adapter must not be nil")
	}

	name := normalizeAdapterName(string(adapter.Name()))
	if name == "" {
		return fmt.Errorf("inventory adapter name must not be empty")
	}

	adapterRegistryMu.Lock()
	defer adapterRegistryMu.Unlock()

	if _, exists := adapterRegistry[name]; exists {
		return fmt.Errorf("inventory adapter %q is already registered", name)
	}

	adapterRegistry[name] = adapter
	return nil
}

// UnregisterAdapter removes one adapter from the inventory registry.
func UnregisterAdapter(name core.InventoryAdapter) {
	name = normalizeAdapterName(string(name))
	if name == "" {
		return
	}

	adapterRegistryMu.Lock()
	defer adapterRegistryMu.Unlock()
	delete(adapterRegistry, name)
}

// HasAdapter reports whether one named adapter is registered.
func HasAdapter(name core.InventoryAdapter) bool {
	name = normalizeAdapterName(string(name))
	if name == "" {
		return false
	}

	adapterRegistryMu.RLock()
	defer adapterRegistryMu.RUnlock()
	_, ok := adapterRegistry[name]
	return ok
}

func parseWithAdapter(data []byte, format core.InventorySourceFormat, sourceName string, adapterName core.InventoryAdapter, options AdapterOptions) (Document, error) {
	adapter, ok := lookupAdapter(adapterName)
	if !ok {
		return Document{}, fmt.Errorf("unsupported inventory adapter %q", adapterName)
	}

	document, err := adapter.Parse(data, format, sourceName, options)
	if err != nil {
		return Document{}, err
	}

	return document, nil
}

func normalizeAdapterName(raw string) core.InventoryAdapter {
	return core.InventoryAdapter(strings.ToLower(strings.TrimSpace(raw)))
}

func lookupAdapter(name core.InventoryAdapter) (Adapter, bool) {
	name = normalizeAdapterName(string(name))

	adapterRegistryMu.RLock()
	defer adapterRegistryMu.RUnlock()

	adapter, ok := adapterRegistry[name]
	return adapter, ok
}
