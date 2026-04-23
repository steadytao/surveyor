// Copyright 2026 The Surveyor Authors
// SPDX-License-Identifier: Apache-2.0

package outputs

import (
	"encoding/json"
	"fmt"

	prioritizereport "github.com/steadytao/surveyor/internal/prioritize"
)

// MarshalPrioritizationJSON serialises a prioritization report as stable,
// indented JSON.
func MarshalPrioritizationJSON(report prioritizereport.Report) ([]byte, error) {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal prioritization report JSON: %w", err)
	}

	return append(data, '\n'), nil
}
