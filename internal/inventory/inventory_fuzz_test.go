// Copyright 2026 The Surveyor Authors
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"testing"

	"github.com/steadytao/surveyor/internal/core"
)

func FuzzParseInventory(f *testing.F) {
	f.Add(byte(0), []byte("version: 1\nentries:\n  - host: example.com\n    ports: [443]\n"))
	f.Add(byte(1), []byte("{\"version\":1,\"entries\":[{\"host\":\"example.com\",\"ports\":[443]}]}"))
	f.Add(byte(2), []byte("host,ports,name\nexample.com,\"443,8443\",primary\n"))
	f.Add(byte(2), []byte(""))

	f.Fuzz(func(t *testing.T, selector byte, data []byte) {
		t.Helper()

		format := core.InventorySourceFormatYAML
		switch selector % 3 {
		case 0:
			format = core.InventorySourceFormatYAML
		case 1:
			format = core.InventorySourceFormatJSON
		case 2:
			format = core.InventorySourceFormatCSV
		}

		_, _ = Parse(data, format, "fuzz")
	})
}
