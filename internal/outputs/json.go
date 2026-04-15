package outputs

import (
	"encoding/json"
	"fmt"

	"github.com/steadytao/surveyor/internal/core"
)

// MarshalJSON serialises a TLS inventory report as stable, indented JSON.
func MarshalJSON(report core.Report) ([]byte, error) {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal report JSON: %w", err)
	}

	return append(data, '\n'), nil
}
