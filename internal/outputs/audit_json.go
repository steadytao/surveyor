package outputs

import (
	"encoding/json"
	"fmt"

	"github.com/steadytao/surveyor/internal/core"
)

func MarshalAuditJSON(report core.AuditReport) ([]byte, error) {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal audit report JSON: %w", err)
	}

	return append(data, '\n'), nil
}
