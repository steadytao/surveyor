// Copyright 2026 The Surveyor Authors
// SPDX-License-Identifier: Apache-2.0

package outputs

import (
	"encoding/json"
	"fmt"

	"github.com/steadytao/surveyor/internal/core"
)

// MarshalAuditJSON serialises an audit report as stable, indented JSON.
func MarshalAuditJSON(report core.AuditReport) ([]byte, error) {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal audit report JSON: %w", err)
	}

	return append(data, '\n'), nil
}
